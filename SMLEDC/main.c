//
//  main.c

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
        
        BIGNUM *g_x = BN_new();
        BIGNUM *g_y =BN_new();
        BIGNUM *g_X = BN_new();
        BIGNUM *g_Z = BN_new();
        
        BIGNUM *p1_x = BN_new();
        BIGNUM *p1_X = BN_new();
        BIGNUM *p1_Z = BN_new();
        BIGNUM *p2_x = BN_new();
        BIGNUM *p2_X = BN_new();
        BIGNUM *p2_Z = BN_new();
        
        BN_hex2bn(&b, _b);
        BN_hex2bn(&g_x, _g_x);
        BN_hex2bn(&g_y, _g_y);
        BN_hex2bn(&f, _f);
        BN_hex2bn(&a, _a);
        

        BIGNUM *A = BN_new();
        BIGNUM *B = BN_new();
        BIGNUM *C = BN_new();
        BIGNUM *D = BN_new();
        BIGNUM *E = BN_new();

        BIGNUM *H = BN_new();
        BIGNUM *I = BN_new();

        BIGNUM *K = BN_new();
        BIGNUM *Q = BN_new();
        BIGNUM *R = BN_new();
        BIGNUM *S = BN_new();
        BIGNUM *T = BN_new();
        BIGNUM *check_left  = BN_new();
        BIGNUM *check_right = BN_new();
        BIGNUM *M = BN_new();
        BIGNUM *N = BN_new();

        
        char *k=  "11011100101000111000101001101110011110101011011010001110000010111011100100110111001010011111010100110111100111100110000101001110011011111101101100011010110100100011110011101101101100111110000101101010101010100101010100101100101000011011101010101000101011101010111010101010001010101010001010111010101010001010101110101010100010101011101010101000101010101110101010100010101010001010101010001010101010111010101010010101010111010101000101010101111101010000001010101000001111010101011110101010000101001011101010100000101011010101110101010100101010110101010101101010101011101010101000101010101101010101010101111101010100101010101110101010100101010000101010101001110101010101110101010001010101010110101010101110101011101010101101010101010100101010010111010101010011101010100000101010010010100110110101010011110101001010101110101001111101010010111110101010010101001010101101010101010100100010101010100101000101010100100101010001010101010101101010101010100101001010101010001010101011101101010101010101110110000001010111111010101101010111101010000010101010100101001010010000101101011010010100101001010100101001001";
        
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
        
        BN_GF2m_mod_mul(Q, p1_X, p2_Z, f, ctx);
        BN_GF2m_mod_mul(R, p2_X, p1_Z, f, ctx);
        BIGNUM *Sq1 = BN_new();
        BIGNUM *Sq2 = BN_new();
        BIGNUM *Sub = BN_new();
        BIGNUM *Sub1 = BN_new();
        
    for(int m=1;m<113;m++)
        {

            
            
            const char tempk = k[m];

            if(atoi(&tempk)==1){

                BN_GF2m_mod_mul(T, p2_X, p2_Z, f, ctx);
                BN_GF2m_mod_mul(S, p1_X, p1_Z, f, ctx);
                BN_GF2m_add(H, Q, R);
                BN_GF2m_mod_mul(I, Q, R, f, ctx);
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
                
                BN_GF2m_mod_mul(T, p2_X, p2_Z, f, ctx);
                BN_GF2m_mod_mul(S, p1_X, p1_Z, f, ctx);
                BN_GF2m_add(H, Q, R);
                BN_GF2m_mod_mul(I, Q, R, f, ctx);
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

            
            if(atoi(&tempk)==1){
                BN_GF2m_add(M, Q, R);

                BN_GF2m_mod_sqr(Sq1, M, f, ctx);
                BN_GF2m_mod_sqr(Sq2, T, f, ctx);
                BN_GF2m_mod_mul(check_left, Sq1, p2_Z, f, ctx);
                BN_GF2m_mod_mul(check_right, Sq2, p1_Z, f, ctx);

                if(BN_cmp(check_left, check_right)==0){
                    BN_GF2m_mod_mul(Q, p1_X, p2_Z, f, ctx);
                    BN_GF2m_mod_mul(R, p2_X, p1_Z, f, ctx);

                    BN_GF2m_mod_mul(Sub1, p1_Z, g_x, f, ctx);
                    BN_GF2m_add(Sub, p1_X, Sub1);
                    BN_GF2m_mod_mul(check_left, Sub, T, f, ctx);
                    BN_GF2m_mod_mul(check_right, S, p2_Z, f, ctx);

                    if(BN_cmp(check_left, check_right)==0)
                        continue;
                    else
                        printf("Errors in check module 2");

                }else{
                    printf("Errors in check modeule 1!");
                }

            }else{
                BN_GF2m_add(M, Q, R);
                BN_GF2m_mod_sqr(Sq1, M, f, ctx);
                BN_GF2m_mod_sqr(Sq2, S, f, ctx);
                BN_GF2m_mod_mul(check_left, Sq1, p1_Z, f, ctx);
                BN_GF2m_mod_mul(check_right, Sq2, p2_Z, f, ctx);

                if(BN_cmp(check_left, check_right)==0){
                    BN_GF2m_mod_mul(Q, p1_X, p2_Z, f, ctx);
                    BN_GF2m_mod_mul(R, p2_X, p1_Z, f, ctx);

                    BN_GF2m_mod_mul(Sub1, p2_Z, g_x, f, ctx);
                    BN_GF2m_add(Sub, p2_X, Sub1);
                    BN_GF2m_mod_mul(check_left, Sub, S, f, ctx);
                    BN_GF2m_mod_mul(check_right, T, p1_Z, f, ctx);
    
                    if(BN_cmp(check_left, check_right)==0)
                        continue;
                    else
                        printf("Errors in check module 2");

                }else{
                    printf("Errors in Check module 1 !\n");
                }

            }
        }

        BN_GF2m_mod_mul(Q, R3_X, R4_Z, f, ctx);
        BN_GF2m_mod_mul(R, R4_X, R3_Z, f, ctx);
        for(int m=1;m<113;m++)
        {

            const char tempk = 0;
            if(tempk==1){
                BN_GF2m_mod_mul(T, R4_X, R4_Z, f, ctx);
                BN_GF2m_mod_mul(S, R3_X, R3_Z, f, ctx);
                BN_GF2m_add(H, Q, R);
                BN_GF2m_mod_mul(I, Q, R, f, ctx);
                BN_GF2m_mod_sqr(R3_Z, H, f, ctx);
                BN_GF2m_mod_mul(K, g_x, R3_Z, f, ctx);
                BN_GF2m_add(R3_X, K, I);

                BN_GF2m_mod_sqr(A, R4_X, f, ctx);
                BN_GF2m_mod_sqr(B, R4_Z, f, ctx);
                BN_GF2m_mod_sqr(C, A, f, ctx);
                BN_GF2m_mod_sqr(D, B, f, ctx);
                BN_GF2m_mod_mul(E, b, D, f, ctx);

                BN_GF2m_mod_mul(R4_Z, A, B, f, ctx);
                BN_GF2m_add(R4_X, C, E);

            }else{

                BN_GF2m_mod_mul(T, R4_X, R4_Z, f, ctx);
                BN_GF2m_mod_mul(S, R3_X, R3_Z, f, ctx);
                BN_GF2m_add(H, Q, R);
                BN_GF2m_mod_mul(I, Q, R, f, ctx);
                BN_GF2m_mod_sqr(R4_Z, H, f, ctx);
                BN_GF2m_mod_mul(K, g_x, R4_Z, f, ctx);
                BN_GF2m_add(R4_X, K, I);

                BN_GF2m_mod_sqr(A, R3_X, f, ctx);
                BN_GF2m_mod_sqr(B, R3_Z, f, ctx);
                BN_GF2m_mod_sqr(C, A, f, ctx);
                BN_GF2m_mod_sqr(D, B, f, ctx);
                BN_GF2m_mod_mul(E, b, D, f, ctx);

                BN_GF2m_mod_mul(R3_Z, A, B, f, ctx);
                BN_GF2m_add(R3_X, C, E);
            }

            if(tempk==1){
                BN_GF2m_add(M, Q, R);

                BN_GF2m_mod_sqr(Sq1, M, f, ctx);
                BN_GF2m_mod_sqr(Sq2, T, f, ctx);
                BN_GF2m_mod_mul(check_left, Sq1, R4_Z, f, ctx);
                BN_GF2m_mod_mul(check_right, Sq2, R3_Z, f, ctx);
                if(BN_cmp(check_left, check_right)==0){
            
                    BN_GF2m_mod_mul(Q, R3_X, R4_Z, f, ctx);
                    BN_GF2m_mod_mul(R, R4_X, R3_Z, f, ctx);

                    BN_GF2m_mod_mul(Sub1, R3_Z, g_x, f, ctx);
                    BN_GF2m_add(Sub, R3_X, Sub1);
                    BN_GF2m_mod_mul(check_left, Sub, T, f, ctx);
                    BN_GF2m_mod_mul(check_right, S, R4_Z, f, ctx);
                    if(BN_cmp(check_left, check_right)==0)
                        continue;
                    else
                        printf("Errors in check module 2");
                }else{
                    printf("Errors in check modeule 1!");
                }
            }else{
                BN_GF2m_add(M, Q, R);
                BN_GF2m_mod_sqr(Sq1, M, f, ctx);
                BN_GF2m_mod_sqr(Sq2, S, f, ctx);
                BN_GF2m_mod_mul(check_left, Sq1, R3_Z, f, ctx);
                BN_GF2m_mod_mul(check_right, Sq2, R4_Z, f, ctx);

                if(BN_cmp(check_left, check_right)==0){
                    BN_GF2m_mod_mul(Q, R3_X, R4_Z, f, ctx);
                    BN_GF2m_mod_mul(R, R4_X, R3_Z, f, ctx);
                    BN_GF2m_mod_mul(Sub1, R4_Z, g_x, f, ctx);
                    BN_GF2m_add(Sub, R4_X, Sub1);
                    BN_GF2m_mod_mul(check_left, Sub, S, f, ctx);
                    BN_GF2m_mod_mul(check_right, T, R3_Z, f, ctx);
                    if(BN_cmp(check_left, check_right)==0)
                        continue;
                    else
                        printf("Errors in check module 2");
                }else{
                    printf("Errors in Check module 1 !\n");
                }
            }
        }
        BIGNUM *R3_x = BN_new();
        BIGNUM *R4_x = BN_new();
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






