// Contains functions necessary to run a single iteration of the ISG Attack on a fresh instance of 
// XMSS / XMSS^MT

#include "isg-attack-xmss.h"

// Treats byte array as a large unsigned integer and increments its value by 1
// Params:
//  u8 *bytes: byte array to increment
//  int num_bytes: length of byte array

int increment_bytes(u8 *bytes, int num_bytes){
	for (int i = 0; i < num_bytes; i++) {
		if (++bytes[i] != 0x00) {
			break;
		}
	}
}

bst* create_node(){
	bst *node = (bst *)malloc(sizeof(bst));
	node->wots_sec_comp1 = NULL;
	node->wots_sec_comp2 = NULL;
	node->ots_pk = NULL;
	node->left = NULL;
	node->right = NULL;

	return node;
}

bst *insert_node(bst *root, bst *wots_node, const xmss_params *params){
	int gl=0;
	bst *temp=root;
	
	if(temp==NULL){
		return wots_node;
	}else{
		
		gl = memcmp(temp->wots_sec_comp1, wots_node->wots_sec_comp1, params->n);
		
		if(gl > 0)
			temp->left = insert_node(temp->left, wots_node, params);
		else if (gl < 0)
			temp->right = insert_node(temp->right, wots_node, params);
		return temp;
	}
}

bst *find_node(bst *root, unsigned char *wots_sec_comp, const xmss_params *params){
	int gl;
	bst *temp = root;
	if(temp==NULL)
		return NULL;
	else{
		gl = memcmp(temp->wots_sec_comp1, wots_sec_comp, params->n);
		if(gl == 0)
			return temp;
		else if(gl > 0)
			return find_node(temp->left, wots_sec_comp, params);
		else if (gl < 0)
			return find_node(temp->right, wots_sec_comp, params);
		
	}
}

void free_tree(bst *root){
	bst *temp = root;
	if(temp!=NULL){
		free_tree(temp->left);
		free_tree(temp->right);
		free(temp->wots_sec_comp1);
		free(temp->wots_sec_comp2);
		free(temp->ots_pk);
		free(temp);
	}
}


void isg_attack_xmss(ISG_Attack_Result* attack_result, long que, long num_sk_guesses[],
                  int num_runtime_checkpoints, int debug) {
	xmss_params params;
	uint32_t oid;
    	int ret = 0;
    	
    	// TODO test more different variants
    	XMSS_STR_TO_OID(&oid, XMSS_VARIANT);
    	XMSS_PARSE_OID(&params, oid);

    	unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    	unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
    	unsigned char *m = malloc(XMSS_MLEN);
	unsigned char *mf = malloc(XMSS_MLEN);
    	unsigned char *mout = malloc(params.sig_bytes + XMSS_MLEN);
    	unsigned long long smlen;
    	unsigned long long mlen;
	unsigned long long no_wots_nodes = 0;
	unsigned char ots_seed[params.n];

	//struct gdsl_bstree 
	bst *SCKTables[params.wots_len];
	bst *wots_node=NULL;

	for(int i=0;i<params.wots_len;i++)
		SCKTables[i] = NULL;

	//initialization of xmss^mt    	
	XMSS_KEYPAIR(pk, sk, oid);
	
	printf("\nInitialization Done\n");

	const unsigned char *pub_root = pk;
    	const unsigned char *pub_seed = pk + params.n;
    	unsigned char wots_pk[params.wots_sig_bytes];
	unsigned char wots_pkf[params.wots_sig_bytes];
    	unsigned char leaf[params.n];
    	unsigned char root[params.n];
	unsigned char sig[params.wots_sig_bytes];
	unsigned char sigf[params.wots_sig_bytes];
	int lengths[params.wots_len];
    	unsigned char *mhash = root;
	unsigned int no_sec_comp;
	unsigned int sec_comp_idx[2];
    	unsigned long long idx = 0;
    	unsigned int i,j;
    	uint32_t idx_leaf;
	unsigned int no_iterations=0;
	uint32_t ots_addr[8];
    	uint32_t ltree_addr[8];
    	uint32_t node_addr[8];
	
	unsigned char temp_comp[params.n];


	unsigned int temp_no_iterations;
	int temp_d;
	int no_nodes=(1 << params.tree_height);

	//Initialize success of attack to failure
	attack_result->success_guess = -1;

	clock_t temp_time;
	clock_t uncounted_time = 0;
	clock_t attack_start_time = clock();

	//query phase
	printf("\nQuery Phase Starts\n");
	for(no_iterations=0; no_iterations<que; no_iterations++){

		temp_time = clock();
		unsigned char *sm = malloc(params.sig_bytes + XMSS_MLEN);
		//choose a random message m
		randombytes(m, XMSS_MLEN);
	
		//sign message m and get signature sm
		XMSS_SIGN(sk, sm, &smlen, m, XMSS_MLEN);
		uncounted_time += clock() - temp_time;
		
		//XMSS_SIGN_OPEN(mout, &mlen, sm, smlen, pk);
		for(i=0;i<8;i++){
			ots_addr[i] = 0; ltree_addr[i] = 0; node_addr[i] = 0;
		}
    		set_type(ots_addr, XMSS_ADDR_TYPE_OTS);
	    	set_type(ltree_addr, XMSS_ADDR_TYPE_LTREE);
	    	set_type(node_addr, XMSS_ADDR_TYPE_HASHTREE);

		mlen = smlen - params.sig_bytes;
		/* Convert the index bytes from the signature to an integer. */
    		idx = bytes_to_ull(sm, params.index_bytes);

    		/* Put the message all the way at the end of the m buffer, so that we can
     	 	* prepend the required other inputs for the hash function. */
    		memcpy(m + params.sig_bytes, sm + params.sig_bytes, mlen);

		/* Compute the message hash. */
		mhash = root;
    		hash_message(&params, mhash, sm + params.index_bytes, pk, idx,
                	m + params.sig_bytes - 4*params.n, mlen);
    		sm += params.index_bytes + params.n;

		temp_no_iterations = no_iterations;
		temp_d=1;
	
		for(j=1;j<params.d;j++){
			if (temp_no_iterations%no_nodes==0){
				temp_d++;
				temp_no_iterations = temp_no_iterations / no_nodes;
			}	
		}		
	
		for (i = 0; i < temp_d; i++){
			idx_leaf = (idx & ((1 << params.tree_height)-1));
        		idx = idx >> params.tree_height;

        		set_layer_addr(ots_addr, i);
        		set_layer_addr(ltree_addr, i);
  			set_layer_addr(node_addr, i);

        		set_tree_addr(ltree_addr, idx);
        		set_tree_addr(ots_addr, idx);
        		set_tree_addr(node_addr, idx);

			/* The WOTS public key is only correct if the signature was correct. */
			set_ots_addr(ots_addr, idx_leaf);

			/* Initially, root = mhash, but on subsequent iterations it is the root
		   	of the subtree below the currently processed subtree. */
			wots_pk_from_sig(&params, wots_pk, sm, root, pub_seed, ots_addr);
		
			/*Compute chain lengths from msg*/
			chain_lengths(&params, lengths, root);
			
			/*Find chains of lengths 0*/
			no_sec_comp = 0;
			j=0;
			while(no_sec_comp < 2 && j<params.wots_len){
				if(lengths[j]==0){
					sec_comp_idx[no_sec_comp]=j;
					no_sec_comp++;
				}
				j++;
			}

			if(no_sec_comp == 2){
				/*Create the tuple using the secret component keys*/	
				wots_node = create_node();
				
				/*Store Key secret component of the wots*/
				wots_node->wots_sec_comp1 = malloc(params.n);
				memcpy(wots_node->wots_sec_comp1, sm + sec_comp_idx[0]*(params.n), params.n);
				/*Store second secret component of the wots*/
				wots_node->wots_sec_comp2 = malloc(params.n);
				memcpy(wots_node->wots_sec_comp2, sm + sec_comp_idx[1]*params.n, params.n);
				/*Store index of second secret component of the wots*/
				wots_node->index = sec_comp_idx[1];
				/*Store ots_addr of the wots*/
				memcpy(wots_node->ots_addr, ots_addr, 32);
				wots_node->ots_pk = malloc(params.wots_sig_bytes);
				/*Store pk of the wots*/
				memcpy(wots_node->ots_pk, wots_pk, params.wots_sig_bytes);
				
				/*store the node in the sec_comp_idx[0]-th SCKTables BST*/
				if(SCKTables[sec_comp_idx[0]]==NULL)
					SCKTables[sec_comp_idx[0]] = insert_node(SCKTables[sec_comp_idx[0]], wots_node, &params);
				else insert_node(SCKTables[sec_comp_idx[0]], wots_node, &params);

				no_wots_nodes++;
				
			}
			
			sm += params.wots_sig_bytes;

        		/* Compute the leaf node using the WOTS public key. */
        		set_ltree_addr(ltree_addr, idx_leaf);
        		l_tree(&params, leaf, wots_pk, pub_seed, ltree_addr);

        		/* Compute the root node of this subtree. */
        		compute_root(&params, root, leaf, idx_leaf, sm, pub_seed, node_addr);
        		sm += params.tree_height*params.n;
		}
		printf("Q%d done\n",no_iterations);
        }
	printf("\nQuery Phase Ends\n");

	printf("\nGuess Phase starts\n");

	unsigned char ots_seed_g[params.n];
	bst *found_element;
	int found;

	for(i=0;i<params.n;i++)
		ots_seed_g[i]= 0;

	printf("\nGuess ots seed initialization Done.\n");
	no_iterations=0;
	int has_succeeded = 0;
	int next_checkpoint_index = 0;
	while (no_iterations < num_sk_guesses[num_runtime_checkpoints-1] && !has_succeeded){
		expand_seed(&params, sig, ots_seed_g);
		
		found_element = NULL;
		found = 0;
		j=0;
		
		/*Find the BST node where first matching happens*/
		while (found==0 && j<params.wots_len){
			found_element = find_node(SCKTables[j], sig+j*params.n, &params);
			if(found_element!=NULL){
				found = j;
			}
			else j++;
		}
		if(found_element!=NULL){
			/*Check the second component*/
			if(memcmp(found_element->wots_sec_comp2, sig+found_element->index*params.n, params.n)){
				/* Choose a random message*/
				randombytes(mf, XMSS_MLEN);
				
				/*Compute the Signature*/
				wots_sign(&params, sigf, mf, ots_seed_g, pub_seed, found_element->ots_addr);

				/*Compute the wots_pk from the forged signature*/
				wots_pk_from_sig(&params, wots_pkf, sigf, mf, pub_seed, found_element->ots_addr);
				
				/*Check the pk from forged signature and the pk from the BST node*/
				if (memcmp(found_element->ots_pk, wots_pkf, params.wots_sig_bytes)==0) {
        				has_succeeded = 1;
					attack_result->success_guess = no_iterations;
     				}
			}
		}
		
		increment_bytes(ots_seed_g, params.n);
		no_iterations++;

		//If this iteration is a checkpoint, record the current intermediate runtime
		if (no_iterations = num_sk_guesses[next_checkpoint_index]) {
			// Record runtime at checkpoint
			attack_result->intermediate_runtimes[next_checkpoint_index] = (clock() - 
			  attack_start_time) - uncounted_time;
			
			// If attack succeeded, the runtime of all the remaining checkpoints is the same
			if (has_succeeded) {
				for (int j = next_checkpoint_index + 1; j < num_runtime_checkpoints; j++) {
					attack_result->intermediate_runtimes[j] = attack_result->
					  intermediate_runtimes[next_checkpoint_index];
				}
			}

			next_checkpoint_index++;
		}
	}
	
	for(i=0;i<params.wots_len;i++)
		free_tree(SCKTables[i]);

	// Memory usage is the size of 
	attack_result->memory_usage =no_wots_nodes * (sizeof(bst)+params.n*2+32+params.wots_sig_bytes);

	// Record number of checkpoints
	attack_result->num_runtime_checkpoints = num_runtime_checkpoints;

	if (debug) {
		printf("\t---ATTACK COMPLETE---\n");
		printf("\tPrinting attack results:\n");
		printf("\t\tNumber of checkpoints:\t%d\n", attack_result->num_runtime_checkpoints);
		printf("\t\tIntermediate runtimes:\t%ld\n", attack_result->intermediate_runtimes[0]);
		for (int i = 1; i < attack_result->num_runtime_checkpoints; i++) {
			printf("\t\t\t\t\t%ld\n", attack_result->intermediate_runtimes[i]);
		}
		printf("\t\tSuccess guess (-1 indicates failure):\t%ld\n", attack_result->success_guess);
		printf("\t\tMemory usage:\t%ld\n", attack_result->memory_usage);
	}

	return;
}

void isg_attack_test(ISG_Attack_Test_Result* test_result, long num_oracle_queries, long num_sk_guesses[], int num_runtime_checkpoints,
                       int num_attack_iterations, int debug){
	//Set up K2SN-MSS implementation before it can be used
	//Seed the random number generator
	//(Note - srand is not cryptographically suitable, but for the purpose of this test it is 
	//  sufficient)
	srand(time(0));
	
	
	//Set value of global variable for secret ots key size
	//chopped_key_size = reduced_sk_size;

	//Ensure compiler does not optimize away pointer
	ISG_Attack_Result single_attack_results;
	//Running runtimes at each checkpoint, number of successes before each checkpoint, and memory 
	//usage
	long intermediate_runtime_sums[num_runtime_checkpoints];
	for (int i = 0; i < num_runtime_checkpoints; i++){
		intermediate_runtime_sums[i] = 0;
	}
	long intermediate_success_sums[num_runtime_checkpoints];
	for (int i = 0; i < num_runtime_checkpoints; i++){
		intermediate_success_sums[i] = 0;
	}
	long memory_usage_sum = 0;

	//Invoke ISG Attack num_attack_iterations times and keep running total of results
	for (int i = 0; i < num_attack_iterations; i++) {
		if (debug) {
			printf("\n---START ATTACK No. %d---\n", i);
		}

		isg_attack_xmss(&single_attack_results, num_oracle_queries, num_sk_guesses, 
				     num_runtime_checkpoints,debug);
		if (debug) {
			printf("---END ATTACK No. %d---\n", i);
		}
		//Add to running totals of results
		for (int i = 0; i < num_runtime_checkpoints; i++) {
			intermediate_runtime_sums[i] += single_attack_results.intermediate_runtimes[i];
			if (single_attack_results.success_guess < num_sk_guesses[i] && 
			      single_attack_results.success_guess >= 0) {
				intermediate_success_sums[i]++;
			}
		}
		memory_usage_sum += single_attack_results.memory_usage;
	} 

	//Calculate average runtimes, success probabilities, and memory usage
	test_result->num_runtime_checkpoints = num_runtime_checkpoints;
	for (int i = 0; i < num_runtime_checkpoints; i++) {
		test_result->average_intermediate_runtimes[i] = ((double) intermediate_runtime_sums[i]) / 
		  ((double) num_attack_iterations);
		test_result->average_intermediate_successes[i] = ((double) intermediate_success_sums[i]) /
		  ((double) num_attack_iterations);
	}
	test_result->average_memory_usage = ((double) memory_usage_sum) / ((double)
	  num_attack_iterations);
	
	return;
}

