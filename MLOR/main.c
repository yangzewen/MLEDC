//
//  main.c


#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>

#define _g_x "9D73616F35F4AB1407D73562C10F"
#define _g_y "A52830277958EE84D1315ED31886"
#define _b "E8BEE4D3E2260744188BE0E9C723"
#define _f "020000000000000000000000000201"

int main(int argc, const char * argv[]) {
    
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *b = BN_new();
    BIGNUM *f = BN_new();
    
    BIGNUM *g_x = BN_new();
    BIGNUM *g_y =BN_new();
    BIGNUM *g_Z = BN_new();
    BIGNUM *g_X = BN_new();

    BIGNUM *p1_X = BN_new();
    BIGNUM *p1_Z = BN_new();
    BIGNUM *p2_X = BN_new();
    BIGNUM *p2_Z = BN_new();
    
    BN_hex2bn(&b, _b);
    BN_hex2bn(&g_x, _g_x);
    BN_hex2bn(&g_y, _g_y);
    BN_hex2bn(&f, _f);
   
    BIGNUM *A = BN_new();
    BIGNUM *B = BN_new();
    BIGNUM *C = BN_new();
    BIGNUM *D = BN_new();
    BIGNUM *E = BN_new();
    BIGNUM *F = BN_new();
    BIGNUM *G = BN_new();
    BIGNUM *H = BN_new();
    BIGNUM *I = BN_new();
    BIGNUM *K = BN_new();
    

char *k=  "11011100101000111000101001101110011110101011011010001110000010111011100100110111001010011111010100110111100111100110000101001110011011111101101100011010110100100011110011101101101100111110000";


    BN_rand(g_Z, 113, -1, 0);
    BN_GF2m_mod_mul(g_X, g_x, g_Z, f, ctx);
    
    BN_copy(p1_Z, g_Z);
    BN_copy(p1_X, g_X);
    
    BN_GF2m_mod_sqr(A, p1_X, f, ctx);
    BN_GF2m_mod_sqr(B, p1_Z, f, ctx);
    BN_GF2m_mod_mul(p2_Z, A, B, f, ctx);
    BN_GF2m_mod_sqr(C, A, f, ctx);
    BN_GF2m_mod_sqr(D, B, f, ctx);
    BN_GF2m_mod_mul(E, b, D, f, ctx);
    BN_GF2m_add(p2_X, C, E);
    
    for(int m=1;m<113;m++)
    {
        const char tempk = k[m];

            if(atoi(&tempk)==1){
                BN_GF2m_mod_mul(F, p1_X, p2_Z, f, ctx);
                BN_GF2m_mod_mul(G, p2_X, p1_Z, f, ctx);
                BN_GF2m_add(H, F, G);
                BN_GF2m_mod_mul(I, F, G, f, ctx);
                BN_GF2m_mod_sqr(p1_Z, H, f, ctx);
                BN_GF2m_mod_mul(K, g_x, p1_Z, f, ctx);
                BN_GF2m_add(p1_X, K, I);
                
                BN_GF2m_mod_sqr(A, p2_X, f, ctx);
                BN_GF2m_mod_sqr(B, p2_Z, f, ctx);
                BN_GF2m_mod_sqr(C, A, f, ctx);
                BN_GF2m_mod_sqr(D, B, f, ctx);
                BN_GF2m_mod_mul(E, b, D, f, ctx);
                
                BN_GF2m_mod_mul(p2_Z, A, B, f, ctx);
                BN_GF2m_add(p2_X, C, E);
                
            }else{
                
                BN_GF2m_mod_mul(F, p1_X, p2_Z, f, ctx);
                BN_GF2m_mod_mul(G, p2_X, p1_Z, f, ctx);
                BN_GF2m_add(H, F, G);
                BN_GF2m_mod_mul(I, F, G, f, ctx);
                BN_GF2m_mod_sqr(p2_Z, H, f, ctx);
                BN_GF2m_mod_mul(K, g_x, p2_Z, f, ctx);
                BN_GF2m_add(p2_X, K, I);
                
                BN_GF2m_mod_sqr(A, p1_X, f, ctx);
                BN_GF2m_mod_sqr(B, p1_Z, f, ctx);
                BN_GF2m_mod_sqr(C, A, f, ctx);
                BN_GF2m_mod_sqr(D, B, f, ctx);
                BN_GF2m_mod_mul(E, b, D, f, ctx);
                
                BN_GF2m_mod_mul(p1_Z, A, B, f, ctx);
                BN_GF2m_add(p1_X, C, E);
               
            }
        
    }

    
    
    BN_CTX_free(ctx);
    return 0;
}




