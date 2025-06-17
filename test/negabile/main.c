// Coded by Pietro Squilla
// BETA per la crittografia negabile
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <stdint.h> // per uint64_t

#define ENC_KEY_LENGTH 32
#define MAC_KEY_LENGTH 32
#define KEY_LENGTH (ENC_KEY_LENGTH + MAC_KEY_LENGTH)
#define SALT_LENGTH 16
#define NONCE_LENGTH 16
#define TAG_LENGTH 32
#define PBKDF2_ITERATIONS 600000
#define CHUNK_SIZE (64 * 1024)

// header universale per tutti i file, che contengano 1 o 2 crittogrammi
typedef struct {
    uint64_t block1_size;
    uint64_t block2_size;
} ContainerHeader;


void handle_openssl_errors(void);
int derive_keys(const char *password, const unsigned char *salt, unsigned char *enc_key, unsigned char *mac_key);
int get_password(const char *prompt, char *buffer, size_t size);
int confirm_overwrite(const char *filepath);
void encrypt_standard_padded(const char *input_path, const char *output_path, const char *password);
void encrypt_deniable(const char *decoy_path, const char *hidden_path, const char *output_path, const char *decoy_pass, const char *hidden_pass);
void decrypt_universal(const char *input_path, const char *output_path, const char *password);
void main_interactive(void);
void main_cli(int argc, char *argv[]);


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
    if(!f_in){ perror("Errore apertura file input per cifratura blocco"); return NULL; }

    fseek(f_in, 0, SEEK_END);
    long long file_size = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);
    if(file_size < 0) { fclose(f_in); return NULL; }

    *block_size = SALT_LENGTH + NONCE_LENGTH + (uint64_t)file_size + TAG_LENGTH;
    unsigned char* output_buffer = malloc(*block_size);
    if (!output_buffer) { fprintf(stderr, "Allocazione memoria fallita\n"); fclose(f_in); return NULL; }

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

int verify_and_decrypt_block(const unsigned char *block_buffer, uint64_t block_size, const char *password, const char *temp_output_path){
    if(block_size < SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH) return 0;
    
    int ret = 0;
    FILE *f_out = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    EVP_MAC_CTX *mac_ctx = NULL;
    EVP_MAC *mac = NULL;
    unsigned char *decrypted_chunk = NULL, *null_bytes = NULL;
    unsigned char enc_key[ENC_KEY_LENGTH], mac_key[MAC_KEY_LENGTH];

    const unsigned char *salt = block_buffer;
    const unsigned char *nonce = block_buffer + SALT_LENGTH;
    const unsigned char *ciphertext = block_buffer + SALT_LENGTH + NONCE_LENGTH;
    uint64_t ciphertext_size = block_size - (SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH);
    const unsigned char *tag_from_file = ciphertext + ciphertext_size;

    if(!derive_keys(password, salt, enc_key, mac_key)) return 0;

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0), OSSL_PARAM_construct_end() };
    mac_ctx = EVP_MAC_CTX_new(mac);
    if (!mac_ctx || !EVP_MAC_init(mac_ctx, mac_key, sizeof(mac_key), params)) handle_openssl_errors();
    EVP_MAC_update(mac_ctx, salt, SALT_LENGTH);
    EVP_MAC_update(mac_ctx, nonce, NONCE_LENGTH);
    EVP_MAC_update(mac_ctx, ciphertext, ciphertext_size);
    
    unsigned char expected_tag[TAG_LENGTH];
    if(!EVP_MAC_final(mac_ctx, expected_tag, NULL, sizeof(expected_tag))) handle_openssl_errors();

    if(CRYPTO_memcmp(tag_from_file, expected_tag, TAG_LENGTH) != 0) goto cleanup;

    f_out = fopen(temp_output_path, "wb");
    if(!f_out){ perror("Errore apertura file temporaneo"); goto cleanup; }

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx || !EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, enc_key, nonce)) handle_openssl_errors();

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


void encrypt_standard_padded(const char *input_path, const char *output_path, const char *password){
    if(!confirm_overwrite(output_path)) return;

    uint64_t real_block_size = 0;
    unsigned char* real_block = create_encrypted_block(input_path, password, &real_block_size);
    if(!real_block){ fprintf(stderr, "Fallimento cifratura.\n"); return; }

    unsigned char* padding_block = malloc(real_block_size);
    if(!padding_block || !RAND_bytes(padding_block, real_block_size)){
        fprintf(stderr, "Fallimento generazione padding.\n"); free(real_block); if (padding_block) free(padding_block); return;
    }

    FILE *f_out = fopen(output_path, "wb");
    if(!f_out){ perror("Impossibile creare output"); free(real_block); free(padding_block); return; }

    ContainerHeader header = {real_block_size, real_block_size};
    fwrite(&header, 1, sizeof(header), f_out);
    fwrite(real_block, 1, real_block_size, f_out);
    fwrite(padding_block, 1, real_block_size, f_out);
    
    printf("\nFile '%s' cifrato con successo (con padding di negabilità) in '%s'.\n", input_path, output_path);
    fclose(f_out);
    free(real_block);
    free(padding_block);
}

void encrypt_deniable(const char *decoy_path, const char *hidden_path, const char *output_path, const char *decoy_pass, const char *hidden_pass){
    if(!confirm_overwrite(output_path)) return;

    uint64_t decoy_block_size = 0;
    unsigned char* decoy_block = create_encrypted_block(decoy_path, decoy_pass, &decoy_block_size);
    if(!decoy_block){ fprintf(stderr, "Fallimento cifratura file esca.\n"); return; }

    uint64_t hidden_block_size = 0;
    unsigned char* hidden_block = create_encrypted_block(hidden_path, hidden_pass, &hidden_block_size);
    if(!hidden_block){ fprintf(stderr, "Fallimento cifratura file nascosto.\n"); free(decoy_block); return; }

    FILE *f_out = fopen(output_path, "wb");
    if(!f_out){ perror("Impossibile creare output"); free(decoy_block); free(hidden_block); return; }

    ContainerHeader header = {decoy_block_size, hidden_block_size};
    fwrite(&header, 1, sizeof(header), f_out);
    fwrite(decoy_block, 1, decoy_block_size, f_out);
    fwrite(hidden_block, 1, hidden_block_size, f_out);
    
    printf("\nContenitore negabile '%s' creato con successo.\n", output_path);
    fclose(f_out);
    free(decoy_block);
    free(hidden_block);
}

void decrypt_universal(const char *input_path, const char *output_path, const char *password){
    if(!confirm_overwrite(output_path)) return;
    
    FILE *f_in = fopen(input_path, "rb");
    if(!f_in){ perror("Errore apertura file input"); return; }

    unsigned char *block1_buffer = NULL;
    unsigned char *block2_buffer = NULL;
    char *temp_output_path = NULL;
    int success = 0;

    ContainerHeader header;
    if(fread(&header, 1, sizeof(header), f_in) != sizeof(header)){
        fprintf(stderr, "Errore: header non valido o file corrotto.\n");
        goto cleanup;
    }

    temp_output_path = malloc(strlen(output_path) + 5);
    if(!temp_output_path){ fprintf(stderr, "Allocazione memoria fallita\n"); goto cleanup; }
    sprintf(temp_output_path, "%s.tmp", output_path);

    // tentativo sul blocco 1
    block1_buffer = malloc(header.block1_size);
    if(!block1_buffer){ fprintf(stderr, "Allocazione memoria fallita\n"); goto cleanup; }

    if(fread(block1_buffer, 1, header.block1_size, f_in) != header.block1_size){
        fprintf(stderr, "Errore lettura blocco 1 dal file.\n");
        goto cleanup;
    }
    
    if(verify_and_decrypt_block(block1_buffer, header.block1_size, password, temp_output_path)){
        if(rename(temp_output_path, output_path) != 0){
            perror("Errore durante la rinomina del file finale");
            // se la rinomina fallisce, il file .tmp esiste ancora, quindi va rimosso
            remove(temp_output_path);
        }else{
            printf("File '%s' decifrato con successo in '%s'.\n", input_path, output_path);
            success = 1;
        }
        
        goto cleanup;
    }
    
    // tentativo sul blocco 2
    block2_buffer = malloc(header.block2_size);
    if(!block2_buffer){ fprintf(stderr, "Allocazione memoria fallita\n"); goto cleanup; }

    if(fread(block2_buffer, 1, header.block2_size, f_in) != header.block2_size){
        fprintf(stderr, "Errore lettura blocco 2 dal file.\n");
        goto cleanup;
    }
    
    if(verify_and_decrypt_block(block2_buffer, header.block2_size, password, temp_output_path)){
        if(rename(temp_output_path, output_path) != 0){
            perror("Errore durante la rinomina del file finale");
            remove(temp_output_path);
        } else {
            printf("File '%s' decifrato con successo in '%s'.\n", input_path, output_path);
            success = 1;
        }
        goto cleanup;
    }
    // se entrambi falliscono, il file .tmp dovrebbe essere già stato rimosso da verify_and_decrypt_block
    
cleanup:
    // se siamo arrivati qui senza successo, stampa l'errore finale
    if(!success){
        fprintf(stderr, "\nERRORE CRITICO: Il messaggio non è autentico! La password è errata o il file è stato manomesso.\n");
    }
    
    free(block1_buffer);
    free(block2_buffer);
    free(temp_output_path);
    
    if(f_in) fclose(f_in);
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
    printf("\n*** OneTimeXOR con Crittografia Negabile Universale ***\n");
    
    while(1){
        printf("\nScegli un'opzione:\n");
        printf("  1) Cifra\n");
        printf("  2) Crittografia negabile\n");
        printf("  3) Decifra\n");
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
            
            encrypt_standard_padded(input_file, output_file, password);
            OPENSSL_cleanse(password, sizeof(password)); OPENSSL_cleanse(pass_confirm, sizeof(pass_confirm));
        }else if(choice == 2){
            char decoy_file[256], hidden_file[256], output_file[256], decoy_pass[256], hidden_pass[256];
            
            printf("Percorso del file ESCA (decoy): ");
            if(!fgets(decoy_file, sizeof(decoy_file), stdin)) break;
            decoy_file[strcspn(decoy_file, "\n")] = 0;
            
            printf("Percorso del file NASCOSTO (hidden): ");
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
