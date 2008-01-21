/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include "tomcrypt.h"

/**
  @file rsa_make_key.c
  RSA key generation, Tom St Denis
*/  

#ifdef LTC_MRSA


/** Sets *prime equal to or larger than *start. Returns CRYPT_OK on success */
int find_next_prime(void *start, void *prime, void* e_bn){
  void *curr, *gcd;
  int primeness;
  int err;

  LTC_ARGCHK(start != NULL);
  LTC_ARGCHK(prime != NULL);

  if((err = mp_init_multi(&curr, &e_bn, &gcd, NULL)) != CRYPT_OK) { return err; }

  if((err = ltc_mp.copy(start, curr)) != CRYPT_OK) { goto error;}
  if((err = ltc_mp.subi(curr, 1, curr)) != CRYPT_OK) { goto error;}
  do {
    if((err = ltc_mp.addi(curr, 1, curr)) != CRYPT_OK) { goto error;}
    if((err = ltc_mp.isprime(curr, &primeness)) != CRYPT_OK) { goto error;}
    if((err = ltc_mp.gcd(curr,e_bn,gcd)) != CRYPT_OK) {goto error;};
  }
  while(primeness != LTC_MP_YES && ltc_mp.compare_d(gcd,1) == LTC_MP_GT);

  if((err = ltc_mp.copy(curr, prime)) != CRYPT_OK) { goto error;}
  err = CRYPT_OK;

 error:
  mp_clear_multi(curr, gcd, NULL);
  return err;
}



/** 
   Make prime p or q for an RSA key-pair according to the algorithm
   in ANSI X9.31-1998. (Note: for internal use only.)
   @return CRYPT_OK if successful, upon error all allocated ram is freed
*/
int make_rsa_prime(void *p1, void* p2, void *Xp, void* e_bn, void* prime){

  void *Y, *tmp1, *tmp2, *tmp3, *gcd, *Y_minus_one, *R;
  int err;
  int primeness;

  if((err = mp_init_multi(&Y, &tmp1, &tmp2, &tmp3, &gcd, &Y_minus_one, &R, NULL)) != CRYPT_OK) { 
    return CRYPT_MEM; 
  }
  
  // Calculate tmp1 = (p2^{-1} mod p1) * p2
  if((err = ltc_mp.invmod(p2, p1, tmp1)) != CRYPT_OK) {goto error;};
  if((err = ltc_mp.mul(tmp1, p2, tmp1)) != CRYPT_OK) {goto error;};
  
  // Calculate tmp2 = (p1^{-1} mod p2) * p1
  if((err = ltc_mp.invmod(p1, p2, tmp2)) != CRYPT_OK) {goto error;};
  if((err = ltc_mp.mul(tmp2, p1, tmp2)) != CRYPT_OK) {goto error;};
  
  
  // Set tmp3 = p1 * p2
  if((err = ltc_mp.mul(p1, p2, tmp3)) != CRYPT_OK) {goto error;};
  
  
  
  // R = tmp1 - tmp2, made positive (if necessary) by adding p1 * p2.
  if((err = ltc_mp.sub(tmp1, tmp2, R)) != CRYPT_OK) {goto error;};
  if(ltc_mp.compare_d(R, 0) == LTC_MP_LT) {
    if((err = ltc_mp.add(R, tmp3, R)) != CRYPT_OK) {goto error;};
  }
  
  // Set Y = Xp + ((R - Xp) mod (p1 * p2)), made larger than Xp if
  // necessary by adding p1 * p2
  if((err = ltc_mp.sub(R, Xp, Y)) != CRYPT_OK) {goto error;};
  if((err = ltc_mp.mpdiv(Y, tmp3, NULL,  Y)) != CRYPT_OK) {goto error;};
  if((err = ltc_mp.add(Xp, Y, Y)) != CRYPT_OK) {goto error;};
  if(ltc_mp.compare(R, Xp) == LTC_MP_LT) {
    if((err = ltc_mp.add(Y, tmp3, Y)) != CRYPT_OK) {goto error;};
  }
  
  
  // Y must be prime, and gcd(Y-1,e) must be 1. Keep adding p1 * p2
  // until these are both true.
  if((err = ltc_mp.subi(Y,1,Y_minus_one)) != CRYPT_OK) {goto error;};
  if((err = ltc_mp.gcd(Y_minus_one,e_bn,gcd)) != CRYPT_OK) {goto error;};
  if((err = ltc_mp.isprime(Y, &primeness)) != CRYPT_OK) {goto error;}
  
  while(primeness != LTC_MP_YES || (ltc_mp.compare_d(gcd,1) != LTC_MP_EQ)){
    if((err = ltc_mp.add(Y, tmp3, Y)) != CRYPT_OK) {goto error;};
    if((err = ltc_mp.subi(Y,1,Y_minus_one)) != CRYPT_OK) {goto error;};
    if((err = ltc_mp.gcd(Y_minus_one, e_bn, gcd)) != CRYPT_OK) {goto error;};
    if((err = ltc_mp.isprime(Y, &primeness)) != CRYPT_OK) {goto error;}
  }
  
  if((err = ltc_mp.copy(Y,prime)) != CRYPT_OK) {goto error;};
  err = CRYPT_OK;
 error:
  mp_clear_multi(R, Y, Y_minus_one, tmp1, tmp2, tmp3, gcd, NULL);
  return err;
}


int random_bn(prng_state *prng, int wprng,
	      int lower_bitlen, int upper_bitlen, void* bn_out){

  int oct_len;
  void *bn;
  int err;
  unsigned char *buf;

  LTC_ARGCHK(bn_out != NULL);

  if ((err = ltc_mp.init(&bn)) != CRYPT_OK){
    return err;
  }
  oct_len = (upper_bitlen >> 3) + (upper_bitlen & 7 ? 1: 0);
  buf = XCALLOC(1, oct_len);
  if (buf == NULL) {
    err =  CRYPT_MEM;
    goto error1;
  }
  do{
    if (prng_descriptor[wprng].read(buf, oct_len, prng) 
	!= (unsigned long)(oct_len)) {
      err = CRYPT_ERROR_READPRNG;
      goto error2;
    }
    if ((err = ltc_mp.unsigned_read(bn, buf, oct_len)) != CRYPT_OK) {
      goto error2;
    }

  }
  while(ltc_mp.count_bits(bn) < lower_bitlen 
	|| ltc_mp.count_bits(bn) > upper_bitlen);

  if((err = ltc_mp.copy(bn, bn_out)) != CRYPT_OK) { goto error2;}
  err = CRYPT_OK;

 error2:
  XFREE(buf);
 error1:
  ltc_mp.deinit(bn);
  return err;
}















  

/*
  
  // Generate X1, X2: 2 numbers between 2^{100 + alpha} and 2^{101 + alpha} -1
  
  
  x_len_bits = 101 + alpha;
  offset = (x_len_octs * 8) - x_len_bits;
  
  buf[0] = buf[0] & (255 >> offset);
  buf[0] = buf[0] | (128 >> offset);
  
  
  if ((err = ltc_mp.unsigned_read(X1, buf, x_len_octs)) != CRYPT_OK) {
    return err;
  }
  
  if (prng_descriptor[wprng].read(buf, x_len_octs, prng) 
      != (unsigned long)(x_len_octs)) {
    err = CRYPT_ERROR_READPRNG;
    goto error;
  }
  buf[0] = buf[0] & (255 >> offset);
  buf[0] = buf[0] | (128 >> offset);
  
  if ((err = ltc_mp.unsigned_read(X2, buf, x_len_octs)) != CRYPT_OK) {
    return err;
  }
  
  // Now, let p1 and p2 be the first primes bigger than X1 and X2
  // respectively such that p1 and p2 are mutually prime with e.
  
  
  if ((err = ltc_mp.addi(X1, 1, p1)) != CRYPT_OK) {
    return err;
  }
  do{
    if ((err = find_next_prime(p1,p1)) != CRYPT_OK) {
      return err;
    }
    if ((err = ltc_mp.gcd(p1,e_bn,gcd)) != CRYPT_OK) {
      return err;
    }
  }
  while(ltc_mp.compare_d(gcd,1) ==LTC_MP_GT);
  
  
  if ((err = ltc_mp.addi(X2, 1, p2)) != CRYPT_OK) {
    return err;
  }
  do{
    if ((err = find_next_prime(p2,p2)) != CRYPT_OK) {
      return err;
    }
    if ((err = ltc_mp.gcd(p2,e_bn,gcd)) != CRYPT_OK) {
      return err;
    }
  }
  while(ltc_mp.compare_d(gcd,1) ==LTC_MP_GT);
    
  
  XFREE(buf);    
  
  
  
  // Generate random X between sqrt(2)(2^{nlen/2 -1}) and (2^{nlen/2} -1)
  
  
  x_len_bits = 512 + (128 * s);
  x_len_octs = (x_len_bits >> 3) + (x_len_bits & 7 ? 1: 0);
  
  buf = XCALLOC(1, x_len_octs);
  if (buf == NULL) {
    err = CRYPT_MEM;
    goto error;
  }
  
  do{
    if (prng_descriptor[wprng].read(buf, x_len_octs, prng) 
	!= (unsigned long)(size/2) ) {
      err = CRYPT_ERROR_READPRNG;
      goto error;
    }
  }
  // ( 0xb6 / 128 = 1.421875 while sqrt(2) = 1.414213...
  // So repeat until the first byte to 0xb6 or higher
  while (buf[0] < 0xb5);
  
  if ((err = ltc_mp.unsigned_read(Xp, buf, size/2)) != CRYPT_OK) {
    return err;
  }
  
  
  //XFREE(buf);
  if((err = ltc_mp.copy(Xp,Xp_out)) != CRYPT_OK) {goto error;};
  err = CRYPT_OK;
 error:
  XFREE(buf);
  mp_clear_multi(X1, X2, p1, p2, Xp, R, Y, tmp1, tmp2, tmp3, e_bn, gcd, NULL);
  return err;
}
  
  

*/


void rsa_keygen_print_bn(char* name, void* bn, int radix){
  char buf[2000];
  ltc_mp.write_radix(bn, buf, radix);
  printf("%s is %s\n", name, buf);
}


/** 
   Create an RSA key according to ANSI X9.31-1998 spec. Note: this requires
   *two* PRNGs, which should have been created using different seeds.
   @param prng1    One active PRNG state 
   @param wprn1    The index of the PRNG desired for prng1
   @param prng2    The other active PRNG state 
   @param wprn2    The index of the PRNG desired for prng2
   @param size     The size of the modulus (key size) desired (octets; must be either 128 or 256)
   @param e        The "e" value (public key). Must be odd; 65537 or larger
   @param key      [out] Destination of a newly created private key pair
   @return CRYPT_OK if successful, upon error all allocated ram is freed
*/
int rsa_make_key(prng_state *prng1, int wprng1, 
		 prng_state *prng2, int wprng2, 
		 int size, long e, rsa_key *key)
{
  void *p1, *p2, *q1, *q2, *Xp, *Xq, *p, *q, *e_bn;
  void *necc_diff, *pq_diff, *XpXq_diff;
  void *tmp1, *tmp2, *tmp3, *tmp4;
  int err;
  int j;
  int alpha = 0;
  int s;  
 
  
  LTC_ARGCHK(ltc_mp.name != NULL);
  LTC_ARGCHK(key         != NULL);
  
  // size must be between 128 and 512
  if ((size < (MIN_RSA_SIZE/8)) || (size > (MAX_RSA_SIZE/8))) {
    return CRYPT_INVALID_KEYSIZE;
  }
  
  // Size must be of form 128 + (s * 32), for some (possibly-zero) s.
  
  s = size - 128;
  if(s != 0) {
    if(s & 31) {
      return CRYPT_INVALID_KEYSIZE;
    }
    else {
      s = (s >> 5);
    }
  }
  
  
  if ((alpha < 0) || (alpha > 20)) {
    return CRYPT_INVALID_ARG;
  }
  
  
  if ((err = prng_is_valid(wprng1)) != CRYPT_OK) {
    return err;
  }
  if ((err = prng_is_valid(wprng2)) != CRYPT_OK) {
    return err;
  }
  

  if ((err = mp_init_multi(&p, &q, &p1, &p2, &q1, &q2, &Xp, &Xq, &tmp1, &tmp2, &tmp3, &tmp4, &necc_diff, &pq_diff, &XpXq_diff, &e_bn,NULL)) != CRYPT_OK) {
    return err;
  }


  //Check that e is odd 
  if (!(e&1)) 
    {
      return CRYPT_INVALID_ARG;
    }
  if((err = ltc_mp.set_int(e_bn, e)) != CRYPT_OK) {goto cleanup;};

  
  

  /* How far apart to p and q, Xp and Xq  need to be? */
  if ((err = ltc_mp.twoexpt(necc_diff, 412 + (128 * s)))!= CRYPT_OK)
    {
      goto cleanup;
    }
  
  
  // First, draw randomness for p and then create p.
  
  
  // p1
  if((err = random_bn(prng1, wprng1, 
		      101+alpha, 102+alpha, p1)) != CRYPT_OK)
    { goto cleanup;}
  //rsa_keygen_print_bn("Xp1", p1, 16);

  if((err = find_next_prime(p1, p1, e_bn)) != CRYPT_OK)
    { goto cleanup;}
  //rsa_keygen_print_bn("p1", p1, 16);
  // p2
  if((err = random_bn(prng1, wprng1, 
		      101+alpha, 102+alpha, p2)) != CRYPT_OK)
    { goto cleanup;}
  //rsa_keygen_print_bn("Xp2", p2, 16);
  if((err = find_next_prime(p2, p2, e_bn)) != CRYPT_OK)
    { goto cleanup;}
  //rsa_keygen_print_bn("p2", p2, 16);
  
  //Xp-- must be larger than sqrt(2) * 2^{512+(128*s)}
  do{
    if((err = random_bn(prng1, wprng1, 
			512+(128*s), 512+(128*s), Xp)) != CRYPT_OK)
      { goto cleanup;}
    //rsa_keygen_print_bn("Xp", Xp, 16);
  
    // copy Xp to tmp, bit-shift tmp to compare MSB of Xp against sqrt(2)
    if((err = ltc_mp.copy(Xp, tmp1)) != CRYPT_OK) { goto cleanup;}
    for(j=0; j< 512+(128*s)-30; j++){
      if((err = ltc_mp.div_2(tmp1,tmp1)) != CRYPT_OK) { goto cleanup;}
    }
  }
  while ( ltc_mp.compare_d(tmp1, 759250125) != LTC_MP_GT);

  //p
  if((err = make_rsa_prime(p1, p2, Xp, e_bn, p)) != CRYPT_OK) { goto cleanup; }
  

    // Now, do the same for q. But repeat until q,p and Xp, Xq are
    // sufficiently far apart, and d is sufficiently large
  do {
    // First, draw randomness for p and then create p.
    
      // q1
    if((err = random_bn(prng2, wprng2, 
			101+alpha, 102+alpha, q1)) != CRYPT_OK)
      { goto cleanup;}  
    //rsa_keygen_print_bn("Xq1", q1, 16);

    if((err = find_next_prime(q1, q1, e_bn)) != CRYPT_OK)
      { goto cleanup;}
    //rsa_keygen_print_bn("q1", q1, 16);
  
    // q2
    if((err = random_bn(prng2, wprng2, 
			101+alpha, 102+alpha, q2)) != CRYPT_OK)
      { goto cleanup;}
    //rsa_keygen_print_bn("Xq2", q2, 16);
  
    if((err = find_next_prime(q2, q2, e_bn)) != CRYPT_OK)
      { goto cleanup;}
    //rsa_keygen_print_bn("q2", q2, 16);

    //Xq-- must be larger than sqrt(2) * 2^{512+(128*s)}
    do{
      if((err = random_bn(prng2, wprng2, 
			  512+(128*s), 512+(128*s), Xq)) != CRYPT_OK)
	  { goto cleanup;}
      //rsa_keygen_print_bn("Xq", Xq, 16);
	
      // copy Xp to tmp, bit-shift tmp to compare MSB of Xq against sqrt(2)
      if((err = ltc_mp.copy(Xq, tmp1)) != CRYPT_OK) { goto cleanup;}
      for(j=0; j< 512+(128*s)-30; j++){
	if((err = ltc_mp.div_2(tmp1,tmp1)) != CRYPT_OK) { goto cleanup;}
      }
    }
    while ( ltc_mp.compare_d(tmp1, 759250125) != LTC_MP_GT);

    //q
    if((err = make_rsa_prime(q1, q2, Xq, e_bn, q)) != CRYPT_OK) { goto cleanup; }
    
    
    
    // Now, calculate diff between p,q and Xp, Xq
    if( ltc_mp.compare(p,q) == LTC_MP_LT ) 
      {
	if ((err = ltc_mp.sub(q,p,pq_diff)) != CRYPT_OK) {goto cleanup;}
      }
    else
      {
	if ((err = ltc_mp.sub(p,q,pq_diff)) != CRYPT_OK) {goto cleanup;}
      }
    if( ltc_mp.compare(Xp,Xq) == LTC_MP_LT ) 
      {
	if ((err = ltc_mp.sub(Xq,Xp,XpXq_diff)) != CRYPT_OK) {goto cleanup;}
      }
    else
      {
	if ((err = ltc_mp.sub(Xp,Xq,XpXq_diff)) != CRYPT_OK) {goto cleanup;}
      }
    // Calculate d and check its bit-length
    //tmp1 = p-1
    if ((err = ltc_mp.subi( p, 1,  tmp1)) != CRYPT_OK)                   { goto errkey; } /* tmp1 = p-1 */
    //tmp2 = q-1
    if ((err = ltc_mp.subi( q, 1,  tmp2)) != CRYPT_OK)                   { goto errkey; } /* tmp2 = q-1 */
    //tmp3 = lcm(p-1,q-1)
    if ((err = ltc_mp.lcm( tmp1,  tmp2,  tmp3)) != CRYPT_OK)              { goto errkey; } /* tmp1 = lcm(p-1, q-1) */
    //tmp4 = d = e^-1 mod lcm(p-1,q-1)
    if ((err = ltc_mp.invmod(e_bn,  tmp3,  tmp4)) != CRYPT_OK)         { goto errkey; } /* key->d = 1/e mod lcm(p-1,q-1) */
    
  }
    while (ltc_mp.compare(pq_diff, necc_diff) == LTC_MP_LT
	   || ltc_mp.compare(XpXq_diff, necc_diff) == LTC_MP_LT
	   || ltc_mp.count_bits(tmp4) < 513 + (128*s));


    
    /* make key */
    

  if ((err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP, &key->p, &key->q, NULL)) != CRYPT_OK) {
    goto errkey;
  }

  if((err = ltc_mp.copy(e_bn, key->e)) != CRYPT_OK) { goto errkey;}
  if((err = ltc_mp.copy(tmp4, key->d)) != CRYPT_OK) { goto errkey;}
  if((err = ltc_mp.copy(p,    key->p)) != CRYPT_OK) { goto errkey;}
  if((err = ltc_mp.copy(q,    key->q)) != CRYPT_OK) { goto errkey;}
  /* key->N = pq */
  if ((err = mp_mul( p,  q,  key->N)) != CRYPT_OK)  { goto errkey; } 
  
  /* optimize for CRT now */
  /* find d mod q-1 and d mod p-1 */
  if ((err = mp_sub_d( p, 1,  tmp1)) != CRYPT_OK)           { goto errkey; } /* tmp1 = q-1 */
  if ((err = mp_sub_d( q, 1,  tmp2)) != CRYPT_OK)           { goto errkey; } /* tmp2 = p-1 */
  if ((err = mp_mod( key->d,  tmp1,  key->dP)) != CRYPT_OK) { goto errkey; } /* dP = d mod p-1 */
  if ((err = mp_mod( key->d,  tmp2,  key->dQ)) != CRYPT_OK) { goto errkey; } /* dQ = d mod q-1 */
  if ((err = mp_invmod( q,  p,  key->qP)) != CRYPT_OK)      { goto errkey; } /* qP = 1/q mod p */
  
  
  /* set key type (in this case it's CRT optimized) */
  key->type = PK_PRIVATE;
  
  /* return ok and free temps */
  err       = CRYPT_OK;
  goto cleanup;

 errkey:
  mp_clear_multi(key->d, key->e, key->N, key->dQ, key->dP, key->qP, key->p, key->q, NULL);

 cleanup:
  mp_clear_multi(p1, p2, q1, q2, Xp, Xq, p, q, e_bn, necc_diff, pq_diff, XpXq_diff,
		  tmp1, tmp2, tmp3, tmp4, NULL);
  return err;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/pk/rsa/rsa_make_key.c,v $ */
/* $Revision: 1.16 $ */
/* $Date: 2007/05/12 14:32:35 $ */
