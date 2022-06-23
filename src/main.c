//########################################################################
// (C) Embedded Systems Lab
// All rights reserved.
// ------------------------------------------------------------
// This document contains proprietary information belonging to
// Research & Development FH OÖ Forschungs und Entwicklungs GmbH.
// Using, passing on and copying of this document or parts of it
// is generally not permitted without prior written authorization.
// ------------------------------------------------------------
// info(at)embedded-lab.at
// https://www.embedded-lab.at/
//########################################################################
// *** File name: main.c
// *** Date of file creation: 2022-02-07
// *** List of autors: Lucas Drack
// ***
// *** C implementation of Carter Yagemann's python Fuzzy Extractor.
// *** Original implementation and more information can be found here:
// *** https://github.com/carter-yagemann/python-fuzzy-extractor
//########################################################################

#include <stdio.h>
#include <sodium.h>
#include <string.h>
#include <assert.h>

#include "CFuzzyExtractor.h"
#include "minunit.h"

//  This project uses minunit for simple unit testing
static char * all_tests();
int tests_run = 0;

HelperData h;

int main(int argc, char** argv) {
    printf("Fuzzy C on the go!\n");

    if (sodium_init() == -1) {
        return -1;
    }
    printf("Sodium initialized!\n");

    
    


    char *result = all_tests();
    if (result != 0) {
        printf("%s\n", result);
    }
    else {
        printf("ALL TESTS PASSED\n");
    }
    printf("Tests run: %d\n", tests_run);
 
    return 0;
}

//  General Test structure:
//    - global HelperData struct h is visible to all tests
//    - initHelperData() happens in all_tests(), so each test accesses an already
//      initialized HelperData struct
//    - first line in each test: freeHelperData(&h). This is to prevent memory leaks
//      caused by failing tests (they return before h can be freed)
//    - then: use h like local variable
//    - final freeHelperData() happens in all_tests()
//  Tests can be disabled by commenting out the lines in all_tests().

static char * testAllocateHelperData() {
    freeHelperData(&h);
    allocateHelperData(&h, 3, 6, 2);
    mu_assert("Error in testAllocateHelperData.", h.length == 3 &&
                                                  h.cipherLen == 6 &&
                                                  h.numHelpers == 2 &&
                                                  h.nonces != 0 &&
                                                  h.masks != 0 &&
                                                  h.ciphers != 0);
    // printHelperData(&h);
    return 0;
}

static char * testFreeUnallocatedHelperData() {
    HelperData help;
    initHelperData(&help);
    freeHelperData(&help);
    return 0;
}

static char * testFreeTwiceHelperData() {
    allocateHelperData(&h, 3, 6, 2);
    freeHelperData(&h);
    freeHelperData(&h);
    return 0;
}

static char * testInitFEProperties() {
    FEProperties p;
    initFEProperties(&p, 16, 4, 0.001);
    mu_assert("Error in initFEProperties.", p.length == 16 &&
                                          p.hamErr == 4 &&
                                          p.repErr == 0.001 &&
                                          p.numHelpers == 599 &&
                                          p.cipherLen == p.length + p.secLen);
    // printFEProperties(&p);
    return 0;
}

static char * testfeGenerateReproduce() {
    freeHelperData(&h);
    FEProperties p;
    const size_t len = 16;
    initFEProperties(&p, len, 4, 0.001);
    unsigned char fingerprint[len];
    unsigned char key[len];
    unsigned char reproduced[len];
    unsigned char reproduced2[len];
    int ret;

    for (size_t i = 0; i < 1; i++)
    {
        randombytes_buf(fingerprint, sizeof(fingerprint));
        memset(key, 0, len);
        memset(reproduced, 0, len);
        memset(reproduced2, 0, len);

        ret = feGenerate(fingerprint, key, len, &h, &p);
        mu_assert("Error: feGenerate failed.", ret == 0);

        printHelperData(&h, false);

        // Test: identical fingerprint produces identical key
        ret = feReproduce(fingerprint, reproduced, len, &h);
        mu_assert("Error: feReproduce failed.", ret == 0);
        mu_assert("Error: could not reproduce key.",
                    memcmp(key, reproduced, len) == 0);

        // Test: repeating the process still yields identical key
        ret = feReproduce(fingerprint, reproduced2, len, &h);
        mu_assert("Error: feReproduce failed.", ret == 0);
        mu_assert("Error: feReproduce yielded different keys for the same value.",
                    memcmp(reproduced, reproduced2, len) == 0);
    }

    freeHelperData(&h);
    return 0;
}

static char * testReproduceBad() {
    freeHelperData(&h);
    FEProperties p;
    const size_t len = 16;
    initFEProperties(&p, len, 4, 0.001);
    unsigned char* fingerprint_orig = "AABBCCDDAABBCCDD";
    unsigned char* fingerprint_good = "ABBBCCDDAABBCCDD";   // 2 bits flipped
    unsigned char* fingerprint_bad  = "A0B00CDDAABBCCDD";   // 13 bits flipped
    unsigned char differentFingerprint[len];
    unsigned char key[len];
    unsigned char reproduced[len];
    int ret;

    ret = feGenerate(fingerprint_orig, key, len, &h, &p);
    mu_assert("Error: feGEnerate failed.", ret == 0);

    ret = feReproduce(fingerprint_good, reproduced, len, &h);
    mu_assert("Error: feReproduce failed.", ret == 0);
    mu_assert("Error: feReproduce couldn't handle 2 bit flips.",
                memcmp(key, reproduced, len) == 0);

    memset(reproduced, 0, len);
    ret = feReproduce(fingerprint_bad, reproduced, len, &h);
    mu_assert("Error: feReproduce failed to fail.", ret == -4);
    mu_assert("Error: feReproduce yielded identical key for bad fingerprint.",
                memcmp(key, reproduced, len) != 0);

    freeHelperData(&h);
    return 0;
}

static char * testReproduceFailsOnDifferentValue() {
    freeHelperData(&h);
    FEProperties p;
    const size_t len = 16;
    initFEProperties(&p, len, 4, 0.001);
    unsigned char* fingerprint = "0123456789ABCDEF";
    unsigned char differentFingerprint[len];
    unsigned char key[len];
    unsigned char reproduced[len];
    int ret;

    ret = feGenerate(fingerprint, key, len, &h, &p);
    mu_assert("Error: feGEnerate failed.", ret == 0);

    for (size_t i = 0; i < 10; i++)
    {
        randombytes_buf(differentFingerprint, len);
        ret = feReproduce(differentFingerprint, reproduced, len, &h);
        mu_assert("Error: feReproduce failed to fail.", ret == -4);
        mu_assert("Error: feReproduce yielded identical key for different values.",
                    memcmp(key, reproduced, len) != 0);
    }

    freeHelperData(&h);
    return 0;
}

static char * testReproduceFuzzyHamErr4() {
    freeHelperData(&h);
    FEProperties p;
    const size_t len = 16;
    initFEProperties(&p, len, 4, 0.001);    // hamErr = 4 -> extractor accepts *at least* 4 bit flips
    unsigned char fingerprint[len];
    unsigned char noisy[len];
    unsigned char key[len];
    unsigned char reproduced[len];
    int ret;

    for (size_t i = 0; i < 100; i++)
    {
        randombytes_buf(fingerprint, len);
        memset(key, 0, len);
        memset(reproduced, 0, len);

        memcpy(noisy, fingerprint, len);
        // Change a random byte, which could flip up to 8 bits
        // for (size_t i = 0; i < 2; i++) {
        //     noisy[randombytes_uniform(len)] = randombytes_uniform(256);
        // }

        // Take a random byte, flip exactly 4 bits
        for (size_t i = 0; i < 1; i++) {
            int n = randombytes_uniform(len);
            noisy[n] = noisy[n] ^ 0xAA;
        }

        ret = feGenerate(fingerprint, key, len, &h, &p);
        mu_assert("Error: feGenerate failed.", ret == 0);

        // Test: noisy fingerprint produces identical key
        ret = feReproduce(noisy, reproduced, len, &h);
        mu_assert("Error: feReproduce failed.", ret == 0);
        mu_assert("Error: reproduced a wrong key.",
                    memcmp(key, reproduced, len) == 0);
    }

    freeHelperData(&h);
    return 0;
}

// Fill 1D array of unsigned char with contents from line
// Line format is CSV delimited by ;
int parseRow(unsigned char* dest, char* line) {
    if (dest == NULL || line == NULL) { return -1; }

    unsigned char* _dest = dest;
    const char* tok;
    for (tok = strtok(line, ";"); tok && *tok; tok = strtok(NULL, ";\n")) {
        if (dest == NULL) { return -2; }
        *_dest++ = (unsigned char)atoi(tok);
    }

    return 0;
}

int printRow(unsigned char* row, const size_t len) {
    if (row == NULL) { return -1; }

    for (size_t i = 0; i < len; i++) {
        printf("%u ", row[i]);
    }
    printf("\n");
    return 0; 
}

int readFingerprintsFromCSV(const char* fnameLatent, const char* fnameKnown,
                            const size_t len, const size_t nReadings,
                            unsigned char knownFP[len], unsigned char latentFP[nReadings][len])
{
        FILE* stream = fopen(fnameLatent, "r");
        if (!stream) { return -1; }

        int i = 0;
        int ret = 0;
        char line[1024];
        while (fgets(line, 1024, stream))
        {
            // printf("%s", line);
            ret = parseRow(latentFP[i++], line);
            // printRow(latentFP[i++], len);
            if (ret != 0) { return -2; }
        }
        fclose(stream);

        stream = fopen(fnameKnown, "r");
        if (!stream) { return -3; }

        fgets(line, 1024, stream);
        ret = parseRow(knownFP, line);
        if (ret != 0) { return -4; }
    }


static char * GenerateT25ReproduceT25_HE4() {
    // First, read the CSV files generated in binaire.
    // The files contain (1) known FP and (2) a list of n latent fingerprints.
    // Fingerprints are 16 bytes long.
    // For my master's thesis, I recorded 50 samples of each board, so we will save 50 latent fingerprints.
    printf("\nGenerateT25ReproduceT25_HE4: Compare known fingerprint (25C) with 50 latent fingerprints (25C).\n");
    printf("   Allowed Hamming Error: 4\n");
    printf("   This test should fail, since the error tolerance is too small.\n");

    int ret = 0;
    char* fnameKnown = "knownFP_b4t25.csv";
    char* fnameLatent = "readings_b4t25.csv";
    const size_t len = 16;
    const size_t nReadings = 50;
    unsigned char knownFP[len];
    unsigned char latentFP[nReadings][len];

    ret = readFingerprintsFromCSV(fnameLatent, fnameKnown, len, nReadings, knownFP, latentFP);
    mu_assert("Error: GenerateT25ReproduceT25 failed to read CSV.", ret == 0);


    freeHelperData(&h);
    FEProperties p;
    initFEProperties(&p, len, 4, 0.001);
    unsigned char key[len];
    unsigned char reproduced[len];

    memset(key, 0, len);

    ret = feGenerate(knownFP, key, len, &h, &p);
    mu_assert("Error: feGenerate failed.", ret == 0);
    // printHelperData(&h, false);

    for (size_t i = 0; i < nReadings; i++)
    {
        // Test: try to unlock the FE with each available reading
        memset(reproduced, 0, len);
        ret = feReproduce(latentFP[i], reproduced, len, &h);
        mu_assert("Error: feReproduce failed.", ret == 0);
        mu_assert("Error: feReproduce reproduced a wrong key.", memcmp(key, reproduced, len) == 0);
    }

    freeHelperData(&h);
    return 0;
}

static char * GenerateT25ReproduceT25() {
    // First, read the CSV files generated in binaire.
    // The files contain (1) known FP and (2) a list of n latent fingerprints.
    // Fingerprints are 16 bytes long.
    // For my master's thesis, I recorded 50 samples of each board, so we will save 50 latent fingerprints.
    printf("\nGenerateT25ReproduceT25: Compare known fingerprint (25C) with 50 latent fingerprints (25C).\n");
    printf("   Allowed Hamming Error: 5\n");
    printf("   This test should be ok.\n");

    int ret = 0;
    char* fnameKnown = "knownFP_b4t25.csv";
    char* fnameLatent = "readings_b4t25.csv";
    const size_t len = 16;
    const size_t nReadings = 50;
    unsigned char knownFP[len];
    unsigned char latentFP[nReadings][len];

    ret = readFingerprintsFromCSV(fnameLatent, fnameKnown, len, nReadings, knownFP, latentFP);
    mu_assert("Error: GenerateT25ReproduceT25 failed to read CSV.", ret == 0);


    freeHelperData(&h);
    FEProperties p;
    initFEProperties(&p, len, 5, 0.001);
    unsigned char key[len];
    unsigned char reproduced[len];

    memset(key, 0, len);

    ret = feGenerate(knownFP, key, len, &h, &p);
    mu_assert("Error: feGenerate failed.", ret == 0);
    // printHelperData(&h, false);

    for (size_t i = 0; i < nReadings; i++)
    {
        // Test: try to unlock the FE with each available reading
        memset(reproduced, 0, len);
        ret = feReproduce(latentFP[i], reproduced, len, &h);
        mu_assert("Error: feReproduce failed.", ret == 0);
        mu_assert("Error: feReproduce reproduced a wrong key.", memcmp(key, reproduced, len) == 0);
    }

    freeHelperData(&h);
    return 0;
}

static char * T25DifferentBoard() {
    // This test compares a known fingerprint from board 4 with latent fingerprints of board 13
    printf("\nT25DifferentBoard: Compare known fingerprint from board #4 with 50 latent fingerprints from board #13.\n");
    printf("   Allowed Hamming Error: 5\n");
    printf("   This test should fail, since the FP come from different boards.\n");

    int ret = 0;
    char* fnameKnown = "knownFP_b4t25.csv";
    char* fnameLatent = "readings_b13t25.csv";
    const size_t len = 16;
    const size_t nReadings = 50;
    unsigned char knownFP[len];
    unsigned char latentFP[nReadings][len];

    ret = readFingerprintsFromCSV(fnameLatent, fnameKnown, len, nReadings, knownFP, latentFP);
    mu_assert("Error: T25DifferentBoard failed to read CSV.", ret == 0);


    freeHelperData(&h);
    FEProperties p;
    initFEProperties(&p, len, 5, 0.001);
    unsigned char key[len];
    unsigned char reproduced[len];

    memset(key, 0, len);

    ret = feGenerate(knownFP, key, len, &h, &p);
    mu_assert("Error: feGenerate failed.", ret == 0);
    // printHelperData(&h, false);

    for (size_t i = 0; i < nReadings; i++)
    {
        // Test: try to unlock the FE with each available reading
        memset(reproduced, 0, len);
        ret = feReproduce(latentFP[i], reproduced, len, &h);
        mu_assert("Error: feReproduce failed.", ret == 0);
        mu_assert("Error: feReproduce could not reconstruct fingerprint.", memcmp(key, reproduced, len) == 0);
    }

    freeHelperData(&h);
    return 0;
}

static char * GenerateT25ReproduceT50() {
    // This test compares a known fingerprint of temperature 25 with latent fingerprints of temperature 50.
    printf("\nGenerateT25ReproduceT50: Compare known fingerprint (25C) with 50 latent fingerprints (50C).\n");
    printf("   Allowed Hamming Error: 5\n");
    printf("   This test should fail, since temperature induced noise is too high.\n");

    int ret = 0;
    char* fnameKnown = "knownFP_b4t25.csv";
    char* fnameLatent = "readings_b4t50.csv";
    const size_t len = 16;
    const size_t nReadings = 50;
    unsigned char knownFP[len];
    unsigned char latentFP[nReadings][len];

    ret = readFingerprintsFromCSV(fnameLatent, fnameKnown, len, nReadings, knownFP, latentFP);
    mu_assert("Error: GenerateT25ReproduceT50 failed to read CSV.", ret == 0);


    freeHelperData(&h);
    FEProperties p;
    initFEProperties(&p, len, 5, 0.001);
    unsigned char key[len];
    unsigned char reproduced[len];

    memset(key, 0, len);

    ret = feGenerate(knownFP, key, len, &h, &p);
    mu_assert("Error: feGenerate failed.", ret == 0);
    // printHelperData(&h, false);

    for (size_t i = 0; i < nReadings; i++)
    {
        // Test: try to unlock the FE with each available reading
        memset(reproduced, 0, len);
        ret = feReproduce(latentFP[i], reproduced, len, &h);
        mu_assert("Error: feReproduce failed.", ret == 0);
        mu_assert("Error: feReproduce reproduced a wrong key.", memcmp(key, reproduced, len) == 0);
    }

    freeHelperData(&h);
    return 0;
}

static char * GenerateT25ReproduceT50_HE8() {
    // This test compares a known fingerprint of temperature 25 with latent fingerprints of temperature 50.
    printf("\nGenerateT25ReproduceT50_HE8: Compare known fingerprint (25C) with 50 latent fingerprints (50C).\n");
    printf("   Allowed Hamming Error: 8\n");
    printf("   This test should be ok, since error tolerance was increased.\n");

    int ret = 0;
    char* fnameKnown = "knownFP_b4t25.csv";
    char* fnameLatent = "readings_b4t50.csv";
    const size_t len = 16;
    const size_t nReadings = 50;
    unsigned char knownFP[len];
    unsigned char latentFP[nReadings][len];

    ret = readFingerprintsFromCSV(fnameLatent, fnameKnown, len, nReadings, knownFP, latentFP);
    mu_assert("Error: GenerateT25ReproduceT50_HE8 failed to read CSV.", ret == 0);


    freeHelperData(&h);
    FEProperties p;
    initFEProperties(&p, len, 8, 0.001);
    unsigned char key[len];
    unsigned char reproduced[len];

    memset(key, 0, len);

    ret = feGenerate(knownFP, key, len, &h, &p);
    mu_assert("Error: feGenerate failed.", ret == 0);
    // printHelperData(&h, false);

    for (size_t i = 0; i < nReadings; i++)
    {
        // Test: try to unlock the FE with each available reading
        memset(reproduced, 0, len);
        ret = feReproduce(latentFP[i], reproduced, len, &h);
        mu_assert("Error: feReproduce failed.", ret == 0);
        mu_assert("Error: feReproduce reproduced a wrong key.", memcmp(key, reproduced, len) == 0);
    }

    freeHelperData(&h);
    return 0;
}


static char * all_tests() {
    initHelperData(&h);

    // Test structs and basic stuff (sanity checks)
    // mu_run_test(testAllocateHelperData);
    // mu_run_test(testFreeUnallocatedHelperData);
    // mu_run_test(testFreeTwiceHelperData);
    // mu_run_test(testInitFEProperties);

    // Test fuzzy extractor
    mu_run_test(testfeGenerateReproduce);
    // mu_run_test(testReproduceBad);
    // mu_run_test(testReproduceFailsOnDifferentValue);
    // mu_run_test(testReproduceFuzzyHamErr4);


    mu_run_test(GenerateT25ReproduceT25_HE4);
    mu_run_test(GenerateT25ReproduceT25);
    mu_run_test(T25DifferentBoard);
    mu_run_test(GenerateT25ReproduceT50);
    mu_run_test(GenerateT25ReproduceT50_HE8);

    freeHelperData(&h);

    return 0;
}
