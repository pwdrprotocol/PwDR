
#include "Rand.h"


//===========================
// description: computes factorial of value vl, i.e., val!
int factorial(int val){

  int res = 1;
  for (int i = 1;i < val + 1; i++){
    res *= i;
  }
  return res;
}
//===========================
//description: computes K out of N combinations (of elements of val)
//In the case where multiple elements are taken at a time (i.e., k > 1), the elements are XORed with each other.
bigint* comb(int N, int K, bigint* val){

  bigint big_temp, *res;
  //int temp = 0;
  int combination_size = factorial(N)/(factorial(K)* factorial(N-K));
  res = (bigint*)malloc(combination_size  * sizeof(mpz_t));
  mpz_init_set_str(big_temp, "0", 10);
  //mpz_init_set_str(zero, "0", 10);
  std::string bitmask(K, 1); // K leading 1's
  bitmask.resize(N, 0); // N-K trailing 0's
  int counter = 0;
  // xor
  do {
    for (int i = 0; i < N; ++i) // [0..N-1] integers
    {
      if (bitmask[i]) {
        std::cout << " : " << i;
        mpz_xor(big_temp, big_temp, val[i]);
      }
    }
    mpz_init_set(res[counter],big_temp);
    counter++;
    mpz_init_set_str(big_temp, "0", 10);
    std::cout << std::endl;
    } while (std::prev_permutation(bitmask.begin(), bitmask.end()));
    return res;
}

// description: Generates a pseudorandom value (by  encrypting "val" given the key and initial vector).
bigint* encrypt(int val, byte* key, int key_size, byte* iv, int byte_){

  string cipher, temp;
  CBC_Mode< AES >::Encryption e;
  bigint* res;
  res = (bigint*)malloc(1 * sizeof(mpz_t));
  unsigned char prn_[byte_];
  e.SetKeyWithIV(key, key_size, iv);
  StringSource sss(to_string(val), true, new StreamTransformationFilter(e, new StringSink(cipher)));
  temp = cipher.substr (0, byte_);// truncate the ciphertext
  memset(prn_, 0x00, byte_ + 1);
  strcpy((char*)prn_, temp.c_str());
  mpz_init(res[0]);
  mpz_import(res[0], byte_, 1, 1, 0, 0, prn_);
  return res;
}

//description: generate all combinations of pseudorandom values that meets the trashold

bloom_filter gen_combinations(byte* key, int key_size, byte* iv, int byte_, int e, int n, int cons, bloom_parameters bf_parameters){

  int total_combination_size;
  int combination_size;
  for (int j=e;j<n+1; j++){
    total_combination_size += factorial(n)/(factorial(j)* factorial(n-j));
  }
  //set BF parameters
  bloom_filter filter(bf_parameters);
  bigint *temp, *vals, *res;
  vals = (bigint*)malloc(n * sizeof(mpz_t));
  // regenerate the pseudorandom values
  mpz_init(vals[0]);
  for(int i = 0; i < n; i++){
    temp = encrypt(i * cons, key, key_size, iv, 16);
    mpz_init_set(vals[i], temp[0]);
  }
  bigint* t;
  for(int j = e; j < n + 1; j++){
    // combine them
    t = comb(n, j, vals);
    combination_size = factorial(n) / (factorial(j) * factorial(n - j));
    for(int i = 0; i < combination_size; i++){
      //insert each element into the Bloom filter
      string s = mpz_get_str(NULL, 10, t[i]);
      filter.insert(s);
      s.clear();
    }
  }
  return filter;
}

//description: Generic Private Verdict Encoding (GPVE) algorithm.
bloom_filter GPVE(byte* key, int key_size, byte* iv, int w, int e, int n, int j, bloom_parameters bf_parameters, bigint*&res){

  int cons= 99999;// it is an arbitrary value used as an offset.
  bigint *temp_1;
  Random rd_;
  temp_1 = (bigint*)malloc(1 * sizeof(mpz_t));
  mpz_init(temp_1[0]);
  mpz_init_set_str(res[0], "0", 10);
  //generate a masking factor
  if(j < n-1){
    res = encrypt(j, key, key_size, iv, 16);
  }
  else if(j == n-1){
    for(int i = 0; i < n-1; i++){
      bigint *temp_2 = encrypt(i, key, key_size, iv, 16);
      mpz_xor(res[0], res[0], temp_2[0]);
    }
  }
  //represent the verdict by 0 or a random value
  if(w == 0){
    mpz_init_set_str(temp_1[0], "0", 10);
  }
  else{
    temp_1 = encrypt(j * cons, key, key_size, iv, 16);
  }
  // mask the verdict's representation
  mpz_xor(res[0], res[0], temp_1[0]);
  //1- generate the combinations
  //2-insert the result into a bloom filter.
  bloom_filter filter(bf_parameters);
  if(j == n-1){
    filter = gen_combinations(key, key_size, iv, 16, e, n, cons, bf_parameters);
  }
  return filter;
}

//description:: Generic Final Verdict Decoding (GFVD) Algorithm
int GFVD(int n, bigint* w, bloom_filter filter){

  bool is_in = false;
  bigint temp, zero;
  mpz_init_set_str(temp, "0", 10);
  mpz_init_set_str(zero, "0", 10);
  //combine all verdicts' representations
  for(int i = 0; i < n ; i++){
    mpz_xor(temp, temp, w[i]);
  }
  // check if the temp s in the bloom filter.
  string ss = mpz_get_str(NULL, 10, temp);
  if(filter.contains(ss)){
    cout<<"\n in gen_combinations test-- is in the BF"<<endl;
    is_in = true;
  }
  //extract the final verdict
  if(mpz_cmp(temp, zero) == 0){
    return 0;
  }
  if(!is_in){
    return 0;
  }
  if(is_in){
    return 1;
  }
  else return 0;
}


int main(){

  int n = 10;// total number of arbiters
  int e = 6;// threshold
  int combination_size = factorial(n)/(factorial(e)* factorial(n-e));
  int total_combination_size = 0;
  for (int j = e; j < n + 1; j++){
    total_combination_size += factorial(n)/(factorial(j)* factorial(n - j));
  }
  //-----------Bloom filter parameters---------
  bloom_parameters bf_parameters;
  bf_parameters.projected_element_count = total_combination_size;
  bf_parameters.false_positive_probability = 0.0000000000009095;
  bf_parameters.random_seed = 0xA5A5A5A5;
  if (!bf_parameters){
    std::cout << "Error - Invalid set of bloom filter parameters!" << std::endl;
  }
  bf_parameters.compute_optimal_parameters();
  byte key[AES::DEFAULT_KEYLENGTH];
  int key_size = AES::DEFAULT_KEYLENGTH;
  byte iv[AES::BLOCKSIZE];
  AutoSeededRandomPool prng;
	prng.GenerateBlock(key, key_size);// seed_: master seed for PRF
  //----------------
  bigint* w_, *temp, *temp_2;
  w_ = (bigint*)malloc(n * sizeof(mpz_t));
  temp_2 = (bigint*)malloc(1 * sizeof(mpz_t));
  int w_1 = 0;
  int w_2 = 0;
  int w[n];
  int f;

  float Dj_ = 0;
  float Dn_ = 0;
  float DR_ = 0;
  int number_of_experiments= 1000;


  for(int j = 0;j < number_of_experiments; j++){


  for (int i = 0; i < n; i++){
    w[i] = 0;
  }
  w[1] = 1;
  w[2] = 1;
  w[3] = 1;
  w[4] = 1;
  // w[5] = 1;
  // w[6] = 1;
  // w[7] = 1;
  // w[9] = 1;
  bigint* res;
  res = (bigint*)malloc(1 * sizeof(mpz_t));
  mpz_init(res[0]);
  bloom_filter filter(bf_parameters);
  mpz_init(temp_2[0]);

  double Dj;//*time
  double Dn;//*time
  double DR;//*time
  double start_Dj = clock();//*time

  double end_Dj;
  double end_Dn;
  for(int i = 0; i < n - 1; i++){
    GPVE(key, key_size, iv, w[i], e, n, i, bf_parameters, temp_2);
    if(i==0){
       end_Dj = clock();//*time
    }
    mpz_init_set(w_[i], temp_2[0]);
    cout<<"\n w_["<<i<<"]:"<<w_[i]<<endl;
  }
  Dj = end_Dj - start_Dj;//*time
  Dj_ += Dj / (double) CLOCKS_PER_SEC;

  double start_Dn = clock();//*time
  filter = GPVE(key, key_size, iv, w[n-1], e, n, n-1, bf_parameters, temp_2);
  end_Dn = clock();
  Dn = end_Dn - start_Dn;//*time
  Dn_ += Dn / (double) CLOCKS_PER_SEC;
  mpz_init_set(w_[n-1], temp_2[0]);
  cout<<"\n w_["<<n-1<<"]:"<<w_[n-1]<<endl;


  double start_DR = clock();//*time
  f = GFVD(n, w_, filter);
  double end_DR = clock();//*time


  DR = end_DR - start_DR;//*time
  DR_ += DR / (double) CLOCKS_PER_SEC;

}

  cout<<"\n\t\t\t ========= FINAL VERDICT:   "<<f<<" =========="<<endl;
  cout<<endl;
  cout<<"\n number_of_experiments: "<<number_of_experiments<<endl;
  cout<<endl;
    cout<<"\n\t\t\t ========= Runtime =========="<<endl;
    cout<<"\n Dj_: "<<Dj_/number_of_experiments<<endl;
    cout<<endl;
    cout<<endl;
    cout<<"\n Dn_: "<<Dn_/number_of_experiments<<endl;
    cout<<endl;
    cout<<endl;
    cout<<"\n DR_: "<<DR_/number_of_experiments<<endl;
    cout<<endl;
    cout<<endl;
}
