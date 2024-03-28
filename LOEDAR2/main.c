//
//  main.c
//  LOEDAR2


#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#define _g_x "9D73616F35F4AB1407D73562C10F"
#define _g_y "A52830277958EE84D1315ED31886"
#define _b "E8BEE4D3E2260744188BE0E9C723"
#define _f "020000000000000000000000000201"
#define _a "3088250CA6E7C7FE649CE85820F7"

int main(int argc, const char * argv[]) {
    
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *b = BN_new();
    BIGNUM *f = BN_new();
    BIGNUM *a = BN_new();
    BN_hex2bn(&a, _a);
    
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
    
        BIGNUM *r = BN_new();
        BIGNUM *Blind_R_X = BN_new();
        BIGNUM *Blind_R_Z = BN_new();
        BN_copy(Blind_R_X, p2_X);
        BN_copy(Blind_R_Z, p2_Z);
        BN_rand(r, 113, -1, 0);
        BN_GF2m_mod_mul(Blind_R_X, r, Blind_R_X, f, ctx);
        BN_GF2m_mod_mul(Blind_R_Z, r, Blind_R_Z, f, ctx);
    
    
        BIGNUM *blind1 = BN_new();
        BIGNUM *blind2 = BN_new();
        BIGNUM *blind3 = BN_new();
        BIGNUM *blind4 = BN_new();
        BIGNUM *blind5 = BN_new();
    
        BIGNUM *R3_X = BN_new();
        BIGNUM *R3_Z = BN_new();
        BIGNUM *R4_X = BN_new();
        BIGNUM *R4_Z = BN_new();
    
        BN_copy(R3_X, Blind_R_X);
        BN_copy(R3_Z, Blind_R_Z);
    
        BN_GF2m_mod_mul(blind1, R3_X, p1_Z, f, ctx);
        BN_GF2m_mod_mul(blind2, p1_X, R3_Z, f, ctx);
        BN_GF2m_add(blind3, blind1, blind2);
        BN_GF2m_mod_mul(blind4, blind1, blind2, f, ctx);
        BN_GF2m_mod_sqr(R4_Z, blind3, f, ctx);
        BN_GF2m_mod_mul(blind5, g_x, R4_Z, f, ctx);
        BN_GF2m_add(R4_X, blind5, blind4);
    
        BN_GF2m_mod_mul(blind1, Blind_R_X, p1_Z, f, ctx);
        BN_GF2m_mod_mul(blind2, p1_X, Blind_R_Z, f, ctx);
        BN_GF2m_add(blind3, blind1, blind2);
        BN_GF2m_mod_mul(blind4, blind1, blind2, f, ctx);
        BN_GF2m_mod_sqr(p1_Z, blind3, f, ctx);
        BN_GF2m_mod_mul(blind5, g_x, p1_Z, f, ctx);
        BN_GF2m_add(p1_X, blind5, blind4);
    
        BN_GF2m_mod_sqr(blind1, Blind_R_X, f, ctx);
        BN_GF2m_mod_sqr(blind2, Blind_R_Z, f, ctx);
        BN_GF2m_mod_sqr(blind3, blind1, f, ctx);
        BN_GF2m_mod_sqr(blind4, blind2, f, ctx);
        BN_GF2m_mod_mul(blind5, b, blind4, f, ctx);
    
        BN_GF2m_mod_mul(p2_Z, blind1, blind2, f, ctx);
        BN_GF2m_add(p2_X, blind3, blind5);
    
    
    BIGNUM *pv_X = BN_new();
    BIGNUM *pv_Z = BN_new();
    BIGNUM *check_left = BN_new();
    BIGNUM *check_right = BN_new();
    BIGNUM *lX = BN_new();
    BIGNUM *lZ = BN_new();
    BIGNUM *rX = BN_new();
    BIGNUM *rZ = BN_new();
    
    
    int n=1;
    const char temp = k[n];
    
    if(atoi(&temp)==1){
        BN_copy(pv_X, p2_X);
        BN_copy(pv_Z, p2_Z);
        
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
        BN_copy(pv_X, p1_X);
        BN_copy(pv_Z, p1_Z);
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
    
    
    int count=0;
    for(int m=2;m<113;m++)
    {
        const char tempk = k[m];
        
            if(atoi(&tempk)==1){
                BN_GF2m_mod_mul(F, pv_X, p2_Z, f, ctx);
                BN_GF2m_mod_mul(G, p2_X, pv_Z, f, ctx);
                BN_GF2m_add(H, F, G);
                BN_GF2m_mod_mul(I, F, G, f, ctx);
                BN_GF2m_mod_sqr(pv_Z, H, f, ctx);
                BN_GF2m_mod_mul(K, g_x, pv_Z, f, ctx);
                BN_GF2m_add(pv_X, K, I);
                
                
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
                BN_GF2m_mod_mul(F, p1_X, pv_Z, f, ctx);
                BN_GF2m_mod_mul(G, pv_X, p1_Z, f, ctx);
                BN_GF2m_add(H, F, G);
                BN_GF2m_mod_mul(I, F, G, f, ctx);
                BN_GF2m_mod_sqr(pv_Z, H, f, ctx);
                BN_GF2m_mod_mul(K, g_x, pv_Z, f, ctx);
                BN_GF2m_add(pv_X, K, I);
                
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
        
        BN_GF2m_mod_mul(F, pv_X, p2_Z, f, ctx);
        BN_GF2m_mod_mul(G, p2_X, pv_Z, f, ctx);
        BN_GF2m_add(H, F, G);
        BN_GF2m_mod_mul(I, F, G, f, ctx);
        BN_GF2m_mod_sqr(lZ, H, f, ctx);
        BN_GF2m_mod_mul(K, g_x, lZ, f, ctx);
        BN_GF2m_add(lX, K, I);
        BN_GF2m_mod_sqr(A, p1_X, f, ctx);
        BN_GF2m_mod_sqr(B, p1_Z, f, ctx);
        BN_GF2m_mod_sqr(C, A, f, ctx);
        BN_GF2m_mod_sqr(D, B, f, ctx);
        BN_GF2m_mod_mul(E, b, D, f, ctx);
        BN_GF2m_mod_mul(rZ, A, B, f, ctx);
        BN_GF2m_add(rX, C, E);
        
        BN_GF2m_mod_mul(check_left, lX, rZ, f, ctx);
        BN_GF2m_mod_mul(check_right, lZ, rX, f, ctx);
        
        if(BN_cmp(check_left, check_right)==0){
            printf("1");
        }else{
            count++;
        }
        
    }

    for (int m=1; m<113; m++) {
        
        BN_GF2m_mod_sqr(A, R3_X, f, ctx);
        BN_GF2m_mod_sqr(B, R3_Z, f, ctx);
        BN_GF2m_mod_sqr(C, A, f, ctx);
        BN_GF2m_mod_sqr(D, B, f, ctx);
        BN_GF2m_mod_mul(E, b, D, f, ctx);
        
        BN_GF2m_mod_mul(R3_Z, A, B, f, ctx);
        BN_GF2m_add(R3_X, C, E);
        
        BN_GF2m_mod_mul(F, R3_X, R4_Z, f, ctx);
        BN_GF2m_mod_mul(G, R4_X, R3_Z, f, ctx);
        BN_GF2m_add(H, F, G);
        BN_GF2m_mod_mul(I, F, G, f, ctx);
        BN_GF2m_mod_sqr(R4_Z, H, f, ctx);
        BN_GF2m_mod_mul(K, g_x, R4_Z, f, ctx);
        BN_GF2m_add(R4_X, K, I);
    }
     
        BIGNUM *R3_x = BN_new();
        BIGNUM *R4_x = BN_new();
    BIGNUM *p1_x = BN_new();
    BIGNUM *p2_x = BN_new();
        BN_GF2m_mod_div(p1_x, p1_X, p1_Z, f, ctx);
        BN_GF2m_mod_div(p2_x, p2_X, p2_Z, f, ctx);
        BN_GF2m_mod_div(R3_x, R3_X, R3_Z, f, ctx);
        BN_GF2m_mod_div(R4_x, R4_X, R4_Z, f, ctx);
    
        BIGNUM *y1A = BN_new();
        BIGNUM *y1B = BN_new();
        BIGNUM *y1C = BN_new();
        BIGNUM *y1D = BN_new();
        BIGNUM *y1E = BN_new();
        BIGNUM *y1F = BN_new();
        BIGNUM *y1G = BN_new();
        BIGNUM *y1H = BN_new();
        BIGNUM *y1 = BN_new();
    
        BN_GF2m_add(y1A, p1_x, g_x);
        BN_GF2m_add(y1B, p2_x, g_x);
        BN_GF2m_mod_sqr(y1C, g_x, f, ctx);
        BN_GF2m_mod_mul(y1E, y1A, y1B, f, ctx);
        BN_GF2m_add(y1F, y1C, y1E);
        BN_GF2m_add(y1G, g_y, y1F);
        BN_GF2m_mod_mul(y1H, y1G, y1A, f, ctx);
        BN_GF2m_mod_div(y1D, y1H, g_x, f, ctx);
        BN_GF2m_add(y1, y1D, g_y);
    
        BIGNUM *R1A = BN_new();
        BIGNUM *R1B = BN_new();
        BIGNUM *R1C = BN_new();
        BIGNUM *R1D = BN_new();
        BIGNUM *R1E = BN_new();
        BIGNUM *R1F = BN_new();
        BIGNUM *R1G = BN_new();
        BIGNUM *R1H = BN_new();
        BIGNUM *y2 = BN_new();
    
        BN_GF2m_add(R1A, R3_x, g_x);
        BN_GF2m_add(R1B, R4_x, g_x);
        BN_GF2m_mod_sqr(R1C, g_x, f, ctx);
        BN_GF2m_mod_mul(R1E, R1A, R1B, f, ctx);
        BN_GF2m_add(R1F, R1C, R1E);
        BN_GF2m_add(R1G, g_y, R1F);
        BN_GF2m_mod_mul(R1H, R1G, R1A, f, ctx);
        BN_GF2m_mod_div(R1D, R1H, g_x, f, ctx);
        BN_GF2m_add(y2, R1D, g_y);

        BIGNUM *y3 = BN_new();
        BN_GF2m_add(y3, R3_x, y2);
    
        BIGNUM *FA = BN_new();
        BIGNUM *FB = BN_new();
        BIGNUM *FC = BN_new();
        BIGNUM *FD = BN_new();
        BIGNUM *FE = BN_new();
        BIGNUM *FF = BN_new();
        BIGNUM *FG = BN_new();
        BIGNUM *FH = BN_new();
    
        BN_GF2m_add(FA, y1, y3);
        BN_GF2m_add(FB, p1_x, R3_x);
        BN_GF2m_mod_inv(FC, FB, f, ctx);
        BN_GF2m_mod_mul(FD, FC, FA, f, ctx);
        BN_GF2m_mod_sqr(FE, FD, f, ctx);
        BN_GF2m_add(FF, FE, FD);
        BN_GF2m_add(FG, FF, FB);
        BN_GF2m_add(FH, a, FG);
    
    BN_CTX_free(ctx);
    return 0;
}





