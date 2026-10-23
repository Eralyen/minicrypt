// Entropy collection and CSPRNG

if not globals.hasIndex("minicrypt") then minicrypt = {}
import_code("./error.ms")
import_code("./blake3.ms")
import_code("./chacha20-poly1305.ms")

__scope = function //-------------

minicrypt.Random = {}
minicrypt.Random.seed = null

minicrypt.Random.harvestEntropy = function(timeout = 1)
    start = time
    min_sample = 1000
    bits = 128
    counter = {}
    sample = []
    while true
        if time - start > timeout then return minicrypt.Error("minicrypt.Random.harvestEntropy", "timeout")
        // Get 128 samples, then guesstimate how much entropy they might have
        for _ in range(bits-1)
            sample.push(0)
            // Check how many additions you can perform in 0.0001s
            t = time
            while time - t < 0.0001
                sample[-1] = sample[-1] + 1
            end while
            if not counter.hasIndex(sample[-1]) then counter[sample[-1]] = 0
            counter[sample[-1]] = counter[sample[-1]] + 1
        end for
        mode_ctr = 0
        mode_i = 0
        if sample.len >= min_sample then
            // Find index of the mode
            for i in counter.indexes
                val = counter[i]
                if val > mode_ctr then
                    mode_i = i
                    mode_ctr = val
                end if
            end for
            // (cryptographers pls avert your eyes)
            // Sample amount - sample mode = good enough entropy guesstimate
            entropy = sample.len - mode_ctr
            if entropy >= bits then break
        end if
    end while
    hash_state = minicrypt.BLAKE3.startHash
    minicrypt.BLAKE3.updateHash(hash_state, sample, sample.len * 4)
    self.seed = minicrypt.BLAKE3.finalizeHash(hash_state, 11)
end function

minicrypt.Random.init = function
    if self.seed == null then
        res = self.harvestEntropy
        if typeof(res) == "error" then return res
        self.state = minicrypt.ChaCha8.assembleState(self.seed[:8], self.seed[8:], 0)
        self.output = []
    end if
end function

minicrypt.Random.getRandomWords = function(n_words)
    if self.seed == null then return minicrypt.Error("minicrypt.Random.getRandomWords", "unseeded")
    while self.output.len < n_words 
        output = [0] * 16
        minicrypt.ChaCha8.chachaBlock(output, self.state)
        self.state[12] = self.state[12] + 1
        self.output = self.output + output
    end while
    output = self.output[:n_words]
    self.output = self.output[n_words:]
    return output
end function

minicrypt.Random.randint32 = function
    if self.seed == null then return minicrypt.Error("minicrypt.Random.randint32", "unseeded")
    return self.getRandomWords(1)[0]
end function

minicrypt.Random.randint53 = function
    if self.seed == null then return minicrypt.Error("minicrypt.Random.randint53", "unseeded")
    w = self.getRandomWords(2)
    return (w[1] % 2097152) * 4294967296 + w[0]
end function

minicrypt.Random.random = function
    if self.seed == null then return minicrypt.Error("minicrypt.Random.random", "unseeded")
    w = self.getRandomWords(2)
    return ((w[1] % 2097152) + (w[0] / 4294967296)) / 2097152
end function

minicrypt.Random.randrange = function(a, b)
    if a > b then
        tmp = a
        a = b
        b = tmp
    end if
    return a + floor(self.random * (b - a))
end function

end function //-------------

if not minicrypt.hasIndex("Random") then __scope()
globals.remove("__scope")