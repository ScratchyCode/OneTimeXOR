// Coded by Pietro Squilla
// BETA crittografia negabile (padding uniforme) + gestione corretta e definitiva dei file temporanei
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.hh>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <stdint.h>

#define ENC_KEY_LENGTH 32
#define MAC_KEY_LENGTH 32
#define KEY_LENGTH (ENC_KEY_LENGTH + MAC_KEY_LENGTH)
#define SALT_LENGTH 16
#define NONCE_LENGTH 16
#define TAG_LENGTH 32
#define PBKDF2_ITERATIONS 600000
#define CHUNK_SIZE (64 * 1024)

typedef struct{
    uint64_t data1_size;        // dimensione dati reali (salt + nonce + ciphertext + tag) nel blocco 1
    uint64_t data2_size;        // dimensione dati reali nel blocco 2 (0 se non presente)
    uint64_t padded_block_size; // dimensione uniforme di entrambi i blocchi scritti su disco
}UniformHeader;


void handle_openssl_errors(void);
int derive_keys(const char *password, const unsigned char *salt, unsigned char *enc_key, unsigned char *mac_key);
unsigned char* create_encrypted_block(const char *input_path, const char *password, uint64_t *block_size);
int verify_and_decrypt_block(const unsigned char *padded_block_buffer, uint64_t original_data_size, const char *password, const char *temp_output_path);
void encrypt_standard(const char *input_path, const char *output_path, const char *password);
void encrypt_deniable(const char *decoy_path, const char *hidden_path, const char *output_path, const char *decoy_pass, const char *hidden_pass);
void decrypt_universal(const char *input_path, const char *output_path, const char *password);
int get_password(const char *prompt, char *buffer, size_t size);
int confirm_overwrite(const char *filepath);
void main_interactive(void);
void main_cli(int argc, char *argv[]);


uint64_t max_uint64(uint64_t a, uint64_t b) {
    return (a > b) ? a : b;
}

void handle_openssl_errors(void){
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int derive_keys(const char *password, const unsigned char *salt, unsigned char *enc_key, unsigned char *mac_key){
    unsigned char master_key[KEY_LENGTH];
    if(!PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, SALT_LENGTH, PBKDF2_ITERATIONS, EVP_sha256(), KEY_LENGTH, master_key)){
        fprintf(stderr, "Errore nella derivazione delle chiavi con PBKDF2.\n");
        return 0;
    }
    memcpy(enc_key, master_key, ENC_KEY_LENGTH);
    memcpy(mac_key, master_key + ENC_KEY_LENGTH, MAC_KEY_LENGTH);
    OPENSSL_cleanse(master_key, sizeof(master_key));
    return 1;
}

unsigned char* create_encrypted_block(const char *input_path, const char *password, uint64_t *block_size) {
    FILE *f_in = fopen(input_path, "rb");
    if(!f_in){ perror("Errore apertura file input"); return NULL; }

    fseek(f_in, 0, SEEK_END);
    long long file_size = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);
    if(file_size < 0) { fclose(f_in); return NULL; }

    *block_size = SALT_LENGTH + NONCE_LENGTH + (uint64_t)file_size + TAG_LENGTH;
    unsigned char* output_buffer = malloc(*block_size);
    if(!output_buffer){ fprintf(stderr, "Allocazione memoria fallita\n"); fclose(f_in); return NULL; }

    unsigned char *p = output_buffer;
    unsigned char *salt = p; p += SALT_LENGTH;
    unsigned char *nonce = p; p += NONCE_LENGTH;
    unsigned char *ciphertext = p;

    if(!RAND_bytes(salt, SALT_LENGTH) || !RAND_bytes(nonce, NONCE_LENGTH)) handle_openssl_errors();
    
    unsigned char enc_key[ENC_KEY_LENGTH], mac_key[MAC_KEY_LENGTH];
    if(!derive_keys(password, salt, enc_key, mac_key)) { free(output_buffer); fclose(f_in); return NULL; }

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0), OSSL_PARAM_construct_end() };
    EVP_MAC_CTX *mac_ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_init(mac_ctx, mac_key, sizeof(mac_key), params);
    EVP_MAC_update(mac_ctx, salt, SALT_LENGTH);
    EVP_MAC_update(mac_ctx, nonce, NONCE_LENGTH);

    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, enc_key, nonce);
    
    unsigned char *plaintext_chunk = malloc(CHUNK_SIZE);
    unsigned char *encrypted_chunk = malloc(CHUNK_SIZE);
    unsigned char *null_bytes = calloc(CHUNK_SIZE, 1);
    
    size_t bytes_read;
    int len;
    while((bytes_read = fread(plaintext_chunk, 1, CHUNK_SIZE, f_in)) > 0){
        unsigned char keystream_chunk[bytes_read];
        EVP_EncryptUpdate(cipher_ctx, keystream_chunk, &len, null_bytes, bytes_read);
        for(size_t i = 0; i < bytes_read; ++i) encrypted_chunk[i] = plaintext_chunk[i] ^ keystream_chunk[i];
        EVP_MAC_update(mac_ctx, encrypted_chunk, bytes_read);
        memcpy(ciphertext, encrypted_chunk, bytes_read);
        ciphertext += bytes_read;
    }

    size_t tag_len;
    EVP_MAC_final(mac_ctx, ciphertext, &tag_len, TAG_LENGTH);
    
    EVP_CIPHER_CTX_free(cipher_ctx);
    EVP_MAC_CTX_free(mac_ctx);
    EVP_MAC_free(mac);
    fclose(f_in);
    free(plaintext_chunk);
    free(encrypted_chunk);
    free(null_bytes);
    OPENSSL_cleanse(enc_key, sizeof(enc_key));
    OPENSSL_cleanse(mac_key, sizeof(mac_key));
    return output_buffer;
}

int verify_and_decrypt_block(const unsigned char *padded_block_buffer, uint64_t original_data_size, const char *password, const char *temp_output_path){
    
    if(original_data_size < SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH) return 0;
    
    int ret = 0;
    FILE *f_out = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    EVP_MAC_CTX *mac_ctx = NULL;
    EVP_MAC *mac = NULL;
    unsigned char *decrypted_chunk = NULL, *null_bytes = NULL;
    unsigned char enc_key[ENC_KEY_LENGTH], mac_key[MAC_KEY_LENGTH];

    const unsigned char *salt = padded_block_buffer;
    const unsigned char *nonce = padded_block_buffer + SALT_LENGTH;
    const unsigned char *ciphertext = padded_block_buffer + SALT_LENGTH + NONCE_LENGTH;
    uint64_t ciphertext_size = original_data_size - (SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH);
    const unsigned char *tag_from_file = ciphertext + ciphertext_size;

    if(!derive_keys(password, salt, enc_key, mac_key)) return 0;

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0), OSSL_PARAM_construct_end() };
    mac_ctx = EVP_MAC_CTX_new(mac);
    if(!mac_ctx || !EVP_MAC_init(mac_ctx, mac_key, sizeof(mac_key), params)) handle_openssl_errors();
    EVP_MAC_update(mac_ctx, salt, SALT_LENGTH);
    EVP_MAC_update(mac_ctx, nonce, NONCE_LENGTH);
    EVP_MAC_update(mac_ctx, ciphertext, ciphertext_size);
    
    unsigned char expected_tag[TAG_LENGTH];
    if(!EVP_MAC_final(mac_ctx, expected_tag, NULL, sizeof(expected_tag))) handle_openssl_errors();

    if(CRYPTO_memcmp(tag_from_file, expected_tag, TAG_LENGTH) != 0) goto cleanup;

    f_out = fopen(temp_output_path, "wb");
    if(!f_out){ perror("Errore apertura file temporaneo"); goto cleanup; }

    cipher_ctx = EVP_CIPHER_CTX_new();
    if(!cipher_ctx || !EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, enc_key, nonce)) handle_openssl_errors();

    decrypted_chunk = malloc(CHUNK_SIZE);
    null_bytes = calloc(CHUNK_SIZE, 1);
    
    uint64_t bytes_processed = 0;
    int len;
    while(bytes_processed < ciphertext_size){
        size_t chunk_to_read = ((ciphertext_size - bytes_processed) > CHUNK_SIZE) ? CHUNK_SIZE : (size_t)(ciphertext_size - bytes_processed);
        unsigned char keystream_chunk[chunk_to_read];
        if(!EVP_DecryptUpdate(cipher_ctx, keystream_chunk, &len, null_bytes, chunk_to_read)) handle_openssl_errors();
        for(size_t i = 0; i < chunk_to_read; ++i) decrypted_chunk[i] = ciphertext[bytes_processed + i] ^ keystream_chunk[i];
        if(fwrite(decrypted_chunk, 1, chunk_to_read, f_out) != chunk_to_read) { perror("Errore scrittura file temporaneo"); goto cleanup; }
        bytes_processed += chunk_to_read;
    }
    
    ret = 1;

cleanup:
    if(f_out) fclose(f_out);
    // se la verifica/decifratura fallisce (ret=0), rimuoviamo il file temporaneo;
    // se ha successo (ret=1), lo lasciamo per la funzione chiamante che lo rinominerà;
    if(ret == 0 && temp_output_path) remove(temp_output_path);
    if(cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);
    if(mac_ctx) EVP_MAC_CTX_free(mac_ctx);
    if(mac) EVP_MAC_free(mac);
    free(decrypted_chunk);
    free(null_bytes);
    OPENSSL_cleanse(enc_key, sizeof(enc_key));
    OPENSSL_cleanse(mac_key, sizeof(mac_key));
    return ret;
}

void encrypt_standard(const char *input_path, const char *output_path, const char *password){
    if(!confirm_overwrite(output_path)) return;

    uint64_t data1_size = 0;
    unsigned char* block1_data = create_encrypted_block(input_path, password, &data1_size);
    if(!block1_data){ fprintf(stderr, "Fallimento cifratura.\n"); return; }
    
    uint64_t padded_size = data1_size;

    unsigned char* padded_block1 = calloc(1, padded_size);
    unsigned char* padded_block2 = calloc(1, padded_size);
    if(!padded_block1 || !padded_block2){
         fprintf(stderr, "Fallimento allocazione memoria per padding.\n");
         free(block1_data); free(padded_block1); free(padded_block2); return;
    }
    
    memcpy(padded_block1, block1_data, data1_size);
    RAND_bytes(padded_block2, padded_size); // il secondo blocco è interamente rumore

    FILE *f_out = fopen(output_path, "wb");
    if(!f_out){ perror("Impossibile creare output"); free(block1_data); free(padded_block1); free(padded_block2); return; }

    UniformHeader header = {data1_size, 0, padded_size};
    fwrite(&header, 1, sizeof(header), f_out);
    fwrite(padded_block1, 1, padded_size, f_out);
    fwrite(padded_block2, 1, padded_size, f_out);
    
    printf("\nFile '%s' cifrato con successo in '%s'.\n", input_path, output_path);
    fclose(f_out);
    free(block1_data);
    free(padded_block1);
    free(padded_block2);
}

void encrypt_deniable(const char *decoy_path, const char *hidden_path, const char *output_path, const char *decoy_pass, const char *hidden_pass){
    if(!confirm_overwrite(output_path)) return;

    uint64_t decoy_data_size = 0;
    unsigned char* decoy_block_data = create_encrypted_block(decoy_path, decoy_pass, &decoy_data_size);
    if(!decoy_block_data){ fprintf(stderr, "Fallimento cifratura file esca.\n"); return; }

    uint64_t hidden_data_size = 0;
    unsigned char* hidden_block_data = create_encrypted_block(hidden_path, hidden_pass, &hidden_data_size);
    if(!hidden_block_data){ fprintf(stderr, "Fallimento cifratura file nascosto.\n"); free(decoy_block_data); return; }

    uint64_t padded_size = max_uint64(decoy_data_size, hidden_data_size);
    
    unsigned char* padded_block1 = calloc(1, padded_size);
    unsigned char* padded_block2 = calloc(1, padded_size);

    if(!padded_block1 || !padded_block2){
        fprintf(stderr, "Fallimento allocazione memoria per padding.\n");
        free(decoy_block_data); free(hidden_block_data); free(padded_block1); free(padded_block2); return;
    }
    
    memcpy(padded_block1, decoy_block_data, decoy_data_size);
    RAND_bytes(padded_block1 + decoy_data_size, padded_size - decoy_data_size);

    memcpy(padded_block2, hidden_block_data, hidden_data_size);
    RAND_bytes(padded_block2 + hidden_data_size, padded_size - hidden_data_size);

    FILE *f_out = fopen(output_path, "wb");
    if(!f_out){ perror("Impossibile creare output"); goto cleanup_deniable; }

    UniformHeader header = {decoy_data_size, hidden_data_size, padded_size};
    fwrite(&header, 1, sizeof(header), f_out);
    fwrite(padded_block1, 1, padded_size, f_out);
    fwrite(padded_block2, 1, padded_size, f_out);
    
    printf("\nContenitore negabile '%s' creato con successo.\n", output_path);
    fclose(f_out);

cleanup_deniable:
    free(decoy_block_data);
    free(hidden_block_data);
    free(padded_block1);
    free(padded_block2);
}

void decrypt_universal(const char *input_path, const char *output_path, const char *password){
    if(!confirm_overwrite(output_path)) return;
    
    FILE *f_in = fopen(input_path, "rb");
    if(!f_in){ perror("Errore apertura file input"); return; }

    unsigned char *block_buffer = NULL;
    char *temp_output_path = NULL;
    int success = 0;
    int temp_file_created = 0;

    UniformHeader header;
    if(fread(&header, 1, sizeof(header), f_in) != sizeof(header)){
        fprintf(stderr, "Errore: header non valido o file corrotto.\n");
        fclose(f_in);
        return;
    }

    temp_output_path = malloc(strlen(output_path) + 5);
    if(!temp_output_path){
        fprintf(stderr, "Allocazione memoria fallita\n");
        fclose(f_in);
        return;
    }
    sprintf(temp_output_path, "%s.tmp", output_path);

    block_buffer = malloc(header.padded_block_size);
    if(!block_buffer){
        fprintf(stderr, "Allocazione memoria fallita\n");
        free(temp_output_path);
        fclose(f_in);
        return;
    }

    // tentativo sul blocco 1
    if(fread(block_buffer, 1, header.padded_block_size, f_in) == header.padded_block_size){
        if(header.data1_size > 0){
            temp_file_created = 1; // la funzione helper tenterà di creare il file
            if(verify_and_decrypt_block(block_buffer, header.data1_size, password, temp_output_path)){
                if(rename(temp_output_path, output_path) == 0){
                    success = 1;
                    temp_file_created = 0; // il file è stato rinominato, non più temporaneo
                }else{
                    perror("Errore durante la rinomina del file finale");
                    // lascia temp_file_created a 1, così verrà rimosso alla fine
                }
            }
        }
    } else {
        fprintf(stderr, "Errore lettura blocco 1 dal file.\n");
    }

    // tentativo sul blocco 2 (solo se il primo non ha avuto successo)
    if(!success){
        if(fread(block_buffer, 1, header.padded_block_size, f_in) == header.padded_block_size){
            if(header.data2_size > 0){
                temp_file_created = 1; // la funzione helper tenterà di creare il file
                if(verify_and_decrypt_block(block_buffer, header.data2_size, password, temp_output_path)){
                    if(rename(temp_output_path, output_path) == 0){
                        success = 1;
                        temp_file_created = 0; // il file è stato rinominato, non più temporaneo
                    }else{
                        perror("Errore durante la rinomina del file finale");
                    }
                }
            }
        }else if(header.data2_size > 0){ // non tentare di leggere se non c'è un secondo blocco
             fprintf(stderr, "Errore lettura blocco 2 dal file.\n");
        }
    }
    
    
    if(success){
        printf("File '%s' decifrato con successo in '%s'.\n", input_path, output_path);
    } else {
        fprintf(stderr, "\nERRORE CRITICO: Il messaggio non è autentico! La password è errata o il file è stato manomesso.\n");
    }
    
    // se un file temporaneo è stato creato ma non rinominato con successo --> rimuovilo
    if(temp_file_created){
        remove(temp_output_path);
    }
    
    free(block_buffer);
    free(temp_output_path);
    fclose(f_in);
}


int get_password(const char *prompt, char *buffer, size_t size){
    struct termios old_term, new_term;
    printf("%s", prompt);
    fflush(stdout);
    
    if(tcgetattr(STDIN_FILENO, &old_term) != 0) return -1;
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    
    if(tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_term) != 0) return -1;
    
    char *result = fgets(buffer, size, stdin);
    (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
    
    printf("\n");
    if(!result) return -1;
    buffer[strcspn(buffer, "\n")] = '\0';
    
    return 0;
}

int confirm_overwrite(const char *filepath){
    FILE *file = fopen(filepath, "rb");
    
    if(file){
        fclose(file);
        printf("Il file di output '%s' esiste già. Sovrascriverlo? (s/n): ", filepath);
        int choice = getchar();
        int c;
        while((c = getchar()) != '\n' && c != EOF);
        if(choice != 's' && choice != 'S'){
            printf("Operazione annullata dall'utente.\n");
            return 0;
        }
    }
    
    return 1;
}

void main_interactive(){
    char choice_str[10];
    int choice;
    printf("\n*** OneTimeXOR con Crittografia Negabile ***\n");
    
    while(1){
        printf("\nScegli un'opzione:\n");
        printf("  1) Cifra Singolo File\n");
        printf("  2) Crittografia Negabile\n");
        printf("  3) Decifra File o Contenitore\n");
        printf("  4) Esci\n");
        printf("\nScelta: ");

        if(!fgets(choice_str, sizeof(choice_str), stdin)) break;
        choice = atoi(choice_str);

        if(choice == 1){
            char input_file[256], output_file[256], password[256], pass_confirm[256];
            
            printf("Percorso del file da cifrare: ");
            if(!fgets(input_file, sizeof(input_file), stdin)) break;
            input_file[strcspn(input_file, "\n")] = 0;
            
            printf("Percorso del file di output: ");
            if(!fgets(output_file, sizeof(output_file), stdin)) break;
            output_file[strcspn(output_file, "\n")] = 0;
            
            if(get_password("Inserisci la password: ", password, sizeof(password)) != 0 || strlen(password) == 0) continue;
            if(get_password("Conferma password: ", pass_confirm, sizeof(pass_confirm)) != 0) continue;
            if(strcmp(password, pass_confirm) != 0){ fprintf(stderr, "Le password non coincidono.\n"); continue; }
            
            encrypt_standard(input_file, output_file, password);
            OPENSSL_cleanse(password, sizeof(password)); OPENSSL_cleanse(pass_confirm, sizeof(pass_confirm));
        }else if(choice == 2){
            char decoy_file[256], hidden_file[256], output_file[256], decoy_pass[256], hidden_pass[256];
            
            printf("Percorso del file ESCA: ");
            if(!fgets(decoy_file, sizeof(decoy_file), stdin)) break;
            decoy_file[strcspn(decoy_file, "\n")] = 0;
            
            printf("Percorso del file NASCOSTO: ");
            if(!fgets(hidden_file, sizeof(hidden_file), stdin)) break;
            hidden_file[strcspn(hidden_file, "\n")] = 0;
            
            printf("Percorso del file contenitore di output: ");
            if(!fgets(output_file, sizeof(output_file), stdin)) break;
            output_file[strcspn(output_file, "\n")] = 0;
            
            if(get_password("Password per file ESCA: ", decoy_pass, sizeof(decoy_pass)) != 0 || strlen(decoy_pass) == 0) continue;
            if(get_password("Password per file NASCOSTO: ", hidden_pass, sizeof(hidden_pass)) != 0 || strlen(hidden_pass) == 0) continue;
            if(strcmp(decoy_pass, hidden_pass) == 0){ fprintf(stderr, "Le password DEVONO essere diverse.\n"); continue; }
            
            encrypt_deniable(decoy_file, hidden_file, output_file, decoy_pass, hidden_pass);
            OPENSSL_cleanse(decoy_pass, sizeof(decoy_pass)); OPENSSL_cleanse(hidden_pass, sizeof(hidden_pass));
        }else if(choice == 3){
            char input_file[256], output_file[256], password[256];
            
            printf("Percorso del file da decifrare: ");
            if(!fgets(input_file, sizeof(input_file), stdin)) break;
            input_file[strcspn(input_file, "\n")] = 0;
            
            printf("Percorso del file di output: ");
            if(!fgets(output_file, sizeof(output_file), stdin)) break;
            output_file[strcspn(output_file, "\n")] = 0;
            
            if(get_password("Inserisci la password: ", password, sizeof(password)) != 0 || strlen(password) == 0) continue;
            
            decrypt_universal(input_file, output_file, password);
            OPENSSL_cleanse(password, sizeof(password));
        }else if(choice == 4){
            break;
        }else{
            printf("Scelta non valida.\n");
        }
        printf("----------------------------------------------------\n");
    }
}

void main_cli(int argc, char *argv[]){
     (void)argc;
     (void)argv;
     printf("La modalità a riga di comando non è implementata in questa versione.\n");
     printf("Avviare il programma senza argomenti per la modalità interattiva.\n");
}

int main(int argc, char *argv[]){
    OPENSSL_init_crypto(0, NULL);
    
    if(argc > 1)
        main_cli(argc, argv);
    else
        main_interactive();
    
    return 0;
}
