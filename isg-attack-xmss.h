#ifndef ISG_XMSS_H_
#define ISG_XMSS_H_

#include <stdio.h>
#include <time.h>
#include <gdsl.h>
#include <string.h>
#include <stdlib.h>

#include "xmss.h"
#include "params.h"
#include "randombytes.h"
#include "hash.h"
#include "hash_address.h"
#include "wots.h"
#include "utils.h"
#include "xmss_commons.h"
#include "xmss_core.h"

// Maximum number of checkpoints to record intermediate runtime of attack
#define MAX_NUM_CHECKPOINTS 64

#define XMSS_MLEN 32
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_KEYPAIR xmssmt_keypair
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_SIGN_OPEN xmssmt_sign_open
    #define XMSS_VARIANT "XMSSMT-SHA2_20/2_256"

typedef unsigned char u8;

// Results of an interation of the ISG Attack
// Feel free to modify, add or remove elements, or to remove or replace this struct altogether
typedef struct {
    // Number of intermediate runtimes that will be recorded. Must be less than MAX_NUM_CHECKPOINTS
    int num_runtime_checkpoints;
    // Intermediate runtimes. i^th element is the intermediate runtime of the i^th checkpoint. Extra
    // elements are 0. Element at index num_runtime_checkpoints-1 is the total runtime of the attack.
    clock_t intermediate_runtimes[MAX_NUM_CHECKPOINTS];
    // Iteration number of the Secret-Guessing phase loop of the guess that succeeded, or -1 if the
    // attack did not succeed
    long success_guess;
    // Memory usage to store set of oracle query signature responses
    long memory_usage;
} ISG_Attack_Result;

//Used to store the results of a test of the ISG Attack
typedef struct {
    // Number of intermediate runtimes that will be recorded. Must be less than MAX_NUM_CHECKPOINTS
    int num_runtime_checkpoints;
    // Average intermediate runtimes at each runtime checkpoint. Extra elements are 0. The element 
    // at index num_runtime_checkpoints-1 is the average total runtime.
    double average_intermediate_runtimes[MAX_NUM_CHECKPOINTS];
    // Percentage of attacks that succeeded before each intermediate checkpoint as a decimal. Extra 
    // elements are zero. i^th element is the percentage of attacks that succeeded before the i^th
    // checkpoint.
    double average_intermediate_successes[MAX_NUM_CHECKPOINTS];
    // Average memory usage to store set of oracle query signature responses
    long average_memory_usage;
} ISG_Attack_Test_Result;

// Secret component key table. Essentially an array of length \ell of binary search trees. The i^th
// tree contains an ordered set of tuples. The first element of the tuple is the i^th secret 
// component key of a wots instance. The next element is another secret component key of the same
// wots instance. The remaining elements contain enough information to determine: 1. the location of
// the wots instance in the hyper tree, and 2. the index of the other secret component key. The 
// tuple is keyed by the value of the i^th secret component key.
// Feel free to modify, add or remove elements, or to remove or replace this struct altogether
//typedef struct SCKTables {
//
//} SCKTable;

// A tuple in the secret component key table. The first element of the tuple is the i^th secret 
// component key of a wots instance. The next element is another secret component key of the same
// wots instance. The remaining elements contain enough information to determine: 1. the location of
// the wots instance in the hyper tree, and 2. the index of the other secret component key. The 
// tuple is keyed by the value of the i^th secret component key.
// Feel free to modify, add or remove elements, or to remove or replace this struct altogether
typedef struct bst{
	unsigned char *wots_sec_comp1;
    	unsigned char *wots_sec_comp2;
	int index;
	uint32_t ots_addr[8];
	unsigned char *ots_pk;

	struct bst *left;
	struct bst *right;
}bst;

int increment_bytes(u8 *bytes, int num_bytes);

void isg_attack_xmss(ISG_Attack_Result* attack_result, long num_oracle_queries, long num_sk_guesses[],
                  int num_runtime_checkpoints, int debug);

void isg_attack_test(ISG_Attack_Test_Result* test_result,
                       long num_oracle_queries, long num_sk_guesses[], int num_runtime_checkpoints,
                       int num_attack_iterations, int debug);

//ISGAttackResult isg_attack_xmss(unsigned int que, unsigned int gue);

#endif
