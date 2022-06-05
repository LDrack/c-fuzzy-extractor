// *** Author: Lucas Drack
// *** Created: 2022-02-07
// ***
// *** C implementation of Carter Yagemann's python Fuzzy Extractor.
// *** Original implementation and more information can be found here:
// *** https://github.com/carter-yagemann/python-fuzzy-extractor

#ifndef __C_FUZZYEXTRACTOR_H__
#define __C_FUZZYEXTRACTOR_H__

#include <stdio.h>
#include <stdbool.h>
#include <malloc.h>
#include <math.h>
#include <sodium.h>
#include <assert.h>

// TODO:  libsodium wird als Crypto-Library verwendet.
//        Modern, bietet sicheren RNG und Cryptographie (Pwd-hashing) und ist
//        Cross-compilable - TODO: checken obs wirklich am MC läuft





/*  
 * Struct: HelperData
 * --------------------
 *  Struct that holds helper data used by FuzzyExtractor.
 *  feGenerate() returns a HelperData object.
 *  feReproduce(HD) expects a HelperData object as argument.
 * 
 *  length:     Length in bytes of source values and keys
 *  nonceLen:   Length in bytes of a single nonce/salt (fixed to 16)
 *  cipherLen:  Length in bytes of hashed ciphers
 *  numHelpers: Number of helper values needed for key reproduction
 *  nonces:     Nonces (salts) used during hashing
 *  masks:      Masks that are XOR'd with the values to be hashed.
 *  ciphers:    Ciphers resulting from the hashing algorithm.
 */
typedef struct {
    size_t length;
    size_t nonceLen;
    size_t cipherLen;
    size_t numHelpers;

    unsigned char** nonces;      // char[numHelpers][nonceLen]
    unsigned char** masks;       // char[numHelpers][length]
    unsigned char** ciphers;     // char[numHelpers][cipherLen]
} HelperData;

void initHelperData(HelperData *const h);

void allocateHelperData(HelperData *const h, size_t const length, size_t const cipherLen, size_t const numHelpers);

void freeHelperData(HelperData *const h);

void printHelperData(HelperData *const h, bool const printArrays);


/*  
 * Struct: FEProperties
 * --------------------
 *  length:     Length in bytes of source values and keys.
 *  hamErr:     Hamming error. The number of bits that can be flipped in the source
 *              value and still produce the same key with probability (1 - repErr).
 *  repErr:     Reproduce error. The probability that a source value within hamErr
 *              will not produce the same key (default: 0.001).
 *  secLen:     Security parameter. This is used to determine if the locker is 
 *              unlocked successfully with accuracy (1 - 2 ^ -secLen) (default: 2).
 *  nonceLen:   Length in bytes of nonce (salt) used in digital locker (default: 16).
 *  numHelpers: Calculate the number of helper values needed to be able to 
 *              reproduce keys given hamErr and repErr.
 */
typedef struct {
    size_t length;
    size_t hamErr;
    double repErr;
    size_t secLen;
    size_t nonceLen;
        
    size_t cipherLen;
    size_t numHelpers;
} FEProperties;

void initFEProperties(FEProperties *const p, size_t const length, size_t const hamErr, double const repErr);

void printFEProperties(FEProperties *const p);

/*
 * Function: feGenerate
 * --------------------
 *   Takes a source value and produces a key and public helper data.
 *   This method should be used once at enrollment.
 *
 *   value: the source value
 *   key:   the key derived from the source
 *   len:   length of value and key (bytes)
 *   h:     Public helper data produced by the fuzzy extractor. This 
 *          struct should later be passed as argument to feReproduce().
 *          Important: h holds internal arrays that are dynamically
 *          allocated here. The caller MUST call freeHelperData() on h
 *          before discarding it.
 *   p:     Holds the parameters of the fuzzy extractor. These values
 *          are used to initialize the helper data.
 *
 *   returns: 0 on success, negative int otherwise
 */
int feGenerate(const unsigned char value[], unsigned char key[], 
        const size_t len, HelperData *const h, const FEProperties *const p);

/*
 * Function: feReproduce
 * --------------------
 *   Takes a source value and a public helper and produces a key.
 * 
 *   Given a helper value that matches and a source value that is close 
 *   to those produced by feGenerate, the same key will be produced.
 *
 *   value: the value to reproduce a key for
 *   key:   the reproduced key
 *   len:   length of value and key (bytes)
 *   h:     the previously generated public helper data
 *
 *   returns: 0 on success, negative int otherwise
 */
int feReproduce(const unsigned char value[], unsigned char key[],
        const size_t len, const HelperData *const h);




#endif // __C_FUZZYEXTRACTOR_H__
