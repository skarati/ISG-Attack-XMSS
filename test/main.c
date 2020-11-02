#include <stdio.h>

#include "../isg-attack-xmss.h"

int main(int argc, char *argv[]) {
	int num_attack_iterations, log_q, log_g_s[MAX_NUM_CHECKPOINTS], num_checkpoints,debug = 0;

	//Set test parameters with command line arguments, otherwise use default parameters
	if (argc >= 5) {
		debug = atoi(argv[1]);
		num_attack_iterations = atoi(argv[2]);
		
		log_q = atoi(argv[3]);
		num_checkpoints = argc - 5;
		for (int i = 0; i < num_checkpoints; i++) {
			log_g_s[i] = atoi(argv[i + 5]);
		}
	} else {
		debug = 0;
		num_attack_iterations = 4;
		
		log_q = 2;
		num_checkpoints = 3;
		log_g_s[0] = 0;
		log_g_s[1] = 2;
		log_g_s[2] = 4;
	}
	
	long num_oracle_queries = 0x01 << log_q;
	long num_sk_guesses[MAX_NUM_CHECKPOINTS];
	for (int i = 0; i < num_checkpoints; i++) {
		num_sk_guesses[i] = 0x01 << log_g_s[i];
	}
	ISG_Attack_Test_Result test_result;

	printf("---TEST PARAMETERS---\n");
	//printf("\tChopped key size (bits):\t%d\n", chopped_key_size);
	printf("\tNumber of oracle queries:\t%ld\n", num_oracle_queries);
	printf("\tNumber of checkpoints:\t\t%d\n", num_checkpoints);
	printf("\tNumber of secret-guesses:\t%ld", num_sk_guesses[0]);
	for (int i = 1; i < num_checkpoints; i++) {
		printf(", %ld", num_sk_guesses[i]);
	}
	printf("\n");
	printf("\tNumber of attack iterations:\t%d\n", num_attack_iterations);

	printf("\n---STARTING TEST---\n");
	//Record the real time of the test
	int test_start_time = clock();

	//Run test
	isg_attack_test(&test_result, num_oracle_queries, num_sk_guesses, 
					  num_checkpoints, num_attack_iterations,debug);

	int test_end_time = clock();

	//Print test results
	printf("\n---TEST COMPLETE---\n");
	printf("Printing test results:\n");
	printf("\tAverage runtimes (clock ticks, seconds):\t%lf, %lf\n", 
	         test_result.average_intermediate_runtimes[0], 
			 test_result.average_intermediate_runtimes[0] / ((double) CLOCKS_PER_SEC));
	for (int i = 1; i < test_result.num_runtime_checkpoints; i++) {
		printf("\t\t\t\t\t\t\t%lf, %lf\n", test_result.average_intermediate_runtimes[i], 
			     test_result.average_intermediate_runtimes[i] / ((double) CLOCKS_PER_SEC));
	}
	printf("\tSuccess probabilities:\t%lf\n", test_result.average_intermediate_successes[0]);
	for (int i = 1; i < test_result.num_runtime_checkpoints; i++) {
		printf("\t\t\t\t%lf\n", test_result.average_intermediate_successes[i]);
	}
	printf("\tMemory usage (in bytes):\t%ld\n", test_result.average_memory_usage / 8);
	printf("\tTest real time (seconds):\t%lf\n", ((double) (test_end_time - test_start_time)) / 
	         (double) CLOCKS_PER_SEC);

	return 0;
}
