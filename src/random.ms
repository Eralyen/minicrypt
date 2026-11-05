// Entropy collection and CSPRNG

if not globals.hasIndex("minicrypt") then minicrypt = {}
import_code("./blake3.ms")
import_code("./chacha20-poly1305.ms")
import_code("./error.ms")

__scope = function //-------------
locals.minicrypt = minicrypt
locals.BLAKE3 = minicrypt.BLAKE3
locals.ChaCha8 = minicrypt.ChaCha8
locals.Error = @minicrypt.Error

minicrypt.Random = {}
locals.Random = minicrypt.Random
Random.samples = []
Random.samples_entropy = 0
Random.seed = null
Random.output = []

// When using minicrypt.wait(), harvest this many bits of entropy for the seed before switching to pregenerating a random bytestream
Random.MAX_PREGEN_ENTROPY = 512

// When using minicrypt.wait(), generate these many random words before switching to the wait() intrinsic
Random.MAX_PREGEN_STREAM = 1000

Random.harvestEntropy = function(entropy_bits = 128, timeout = 1)
    start = time
    batch = 128
    counter = {}
    sample = self.samples
    while self.samples_entropy < entropy_bits and time - start < timeout
        // Get 128 samples, then guesstimate how much entropy they might have
        for _ in range(batch-1)
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
        self.samples_entropy = sample.len - mode_ctr
    end while
    if time - start >= timeout then return
    hash_state = BLAKE3.startHash
    BLAKE3.updateHash(hash_state, sample, sample.len * 4)
    self.seed = BLAKE3.finalizeHash(hash_state, 11)
    self.state = ChaCha8.assembleState(self.seed[:8], self.seed[8:], 0)
end function

// Returns an error if the seeding timed out
Random.init = function
    if self.seed == null then
        self.harvestEntropy(128, 10)
        if self.seed == null then return Error("minicrypt.Random.init", "seeding_timed_out")
    end if
end function

Random.pregenWords = function(blocks = 1)
    if self.seed == null then 
        self.harvestEntropy(128, 10)
        if self.seed == null then return null
    end if
    output = [0] * 16
    for i in range(blocks-1)
        ChaCha8.chachaBlock(output, self.state)
        self.state[12] = self.state[12] + 1
        self.output = self.output + output
    end for
end function

// Returns null if the entropy harvesting timed out. Otherwise, returns a list of random 32-bit integers
Random.getRandomWords = function(n_words)
    if self.seed == null then 
        self.harvestEntropy(128, 10)
        if self.seed == null then return null
    end if
    output = [0] * 16
    while self.output.len < n_words 
        ChaCha8.chachaBlock(output, self.state)
        self.state[12] = self.state[12] + 1
        self.output = self.output + output
    end while
    output = self.output[:n_words]
    self.output = self.output[n_words:]
    return output
end function

end function //-------------

if not minicrypt.hasIndex("Random") then __scope()
globals.remove("__scope")