// Coded by Pietro Squilla
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h> // per get_password su sistemi POSIX
#include <unistd.h>  // per get_password su sistemi POSIX
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/crypto.h> // per OPENSSL_init_crypto e OPENSSL_cleanse

#define ENC_KEY_LENGTH 32
#define MAC_KEY_LENGTH 32
#define KEY_LENGTH (ENC_KEY_LENGTH + MAC_KEY_LENGTH)
#define SALT_LENGTH 16
#define NONCE_LENGTH 16
#define TAG_LENGTH 32
#define PBKDF2_ITERATIONS 600000
#define CHUNK_SIZE (64 * 1024)


void handle_openssl_errors(void);
int derive_keys(const char *password, const unsigned char *salt, unsigned char *enc_key, unsigned char *mac_key);
void show_progress(long long current, long long total, const char* message);
void encrypt_file(const char *input_path, const char *output_path, const char *password);
void decrypt_file(const char *input_path, const char *output_path, const char *password);
int get_password(const char *prompt, char *buffer, size_t size);
int confirm_overwrite(const char *filepath);
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

void show_progress(long long current, long long total, const char* message){
    if(total <= 0) {
        printf("\r%s: 100%%", message);
        fflush(stdout);
        return;
    }
    
    int percentage = (int)(100.0 * current / total);
    percentage = (percentage > 100) ? 100 : percentage;
    percentage = (percentage < 0) ? 0 : percentage;
    printf("\r%s: %3d%%", message, percentage);
    fflush(stdout);
}

void encrypt_file(const char *input_path, const char *output_path, const char *password){
    FILE *f_in = NULL, *f_out = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    EVP_MAC_CTX *mac_ctx = NULL;
    EVP_MAC *mac = NULL;
    OSSL_PARAM params[2];
    unsigned char *plaintext_chunk = NULL, *encrypted_chunk = NULL, *null_bytes = NULL;
    unsigned char enc_key[ENC_KEY_LENGTH], mac_key[MAC_KEY_LENGTH];
    int ret = EXIT_FAILURE;

    if(!confirm_overwrite(output_path)) return;

    f_in = fopen(input_path, "rb");
    if(!f_in){ perror("Errore nell'apertura del file di input"); goto cleanup; }

    f_out = fopen(output_path, "wb");
    if(!f_out){ perror("Errore nella creazione del file di output"); goto cleanup; }
    
    plaintext_chunk = malloc(CHUNK_SIZE);
    encrypted_chunk = malloc(CHUNK_SIZE);
    null_bytes = calloc(CHUNK_SIZE, 1);
    if(!plaintext_chunk || !encrypted_chunk || !null_bytes){ fprintf(stderr, "Errore di allocazione della memoria.\n"); goto cleanup; }

    unsigned char salt[SALT_LENGTH], nonce[NONCE_LENGTH];
    if(!RAND_bytes(salt, sizeof(salt)) || !RAND_bytes(nonce, sizeof(nonce))){
        fprintf(stderr, "Errore nella generazione di dati casuali.\n");
        goto cleanup; // deprecato ma amen
    }

    if(!derive_keys(password, salt, enc_key, mac_key)) goto cleanup;
    if(fwrite(salt, 1, sizeof(salt), f_out) != sizeof(salt)) goto io_error;
    if(fwrite(nonce, 1, sizeof(nonce), f_out) != sizeof(nonce)) goto io_error;

    // blocco HMAC moderno (OpenSSL 3.0+)
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if(!mac) handle_openssl_errors();
    
    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    mac_ctx = EVP_MAC_CTX_new(mac);
    if(!mac_ctx) handle_openssl_errors();

    if(!EVP_MAC_init(mac_ctx, mac_key, sizeof(mac_key), params)) handle_openssl_errors();
    if(!EVP_MAC_update(mac_ctx, salt, sizeof(salt))) handle_openssl_errors();
    if(!EVP_MAC_update(mac_ctx, nonce, sizeof(nonce))) handle_openssl_errors();
    // fine blocco HMAC

    cipher_ctx = EVP_CIPHER_CTX_new();
    if(!cipher_ctx || !EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, enc_key, nonce)) handle_openssl_errors();

    fseek(f_in, 0, SEEK_END);
    long long total_size = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);
    long long bytes_processed = 0;

    size_t bytes_read;
    int len;
    
    while((bytes_read = fread(plaintext_chunk, 1, CHUNK_SIZE, f_in)) > 0){
        unsigned char keystream_chunk[bytes_read];
        if(!EVP_EncryptUpdate(cipher_ctx, keystream_chunk, &len, null_bytes, bytes_read)) handle_openssl_errors();
        
        for(size_t i = 0; i < bytes_read; ++i) encrypted_chunk[i] = plaintext_chunk[i] ^ keystream_chunk[i];
        
        if(!EVP_MAC_update(mac_ctx, encrypted_chunk, bytes_read)) handle_openssl_errors();
        if(fwrite(encrypted_chunk, 1, bytes_read, f_out) != bytes_read)
            goto io_error;

        bytes_processed += bytes_read;
        show_progress(bytes_processed, total_size, "Cifratura in corso");
    }
    
    if(total_size == 0) show_progress(0,0,"Cifratura in corso");
    printf("\n");

    unsigned char tag[TAG_LENGTH];
    size_t tag_len;
    
    if(!EVP_MAC_final(mac_ctx, tag, &tag_len, sizeof(tag))) handle_openssl_errors();
    if(tag_len != TAG_LENGTH) { fprintf(stderr, "Errore: lunghezza del tag HMAC non valida.\n"); goto cleanup; }
    if(fwrite(tag, 1, tag_len, f_out) != tag_len) goto io_error;

    printf("File '%s' cifrato e autenticato con successo in '%s'.\n", input_path, output_path);
    ret = EXIT_SUCCESS;
    goto cleanup;

io_error:
    perror("\nErrore di scrittura sul file di output");

cleanup:
    if(cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);
    if(mac_ctx) EVP_MAC_CTX_free(mac_ctx);
    if(mac) EVP_MAC_free(mac);
    if(f_in) fclose(f_in);
    if(f_out) fclose(f_out);
    
    free(plaintext_chunk);
    free(encrypted_chunk);
    free(null_bytes);
    OPENSSL_cleanse(enc_key, sizeof(enc_key));
    OPENSSL_cleanse(mac_key, sizeof(mac_key));
    if(ret == EXIT_FAILURE && output_path) remove(output_path);
}

void decrypt_file(const char *input_path, const char *output_path, const char *password){
    FILE *f_in = NULL, *f_out = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    EVP_MAC_CTX *mac_ctx = NULL;
    EVP_MAC *mac = NULL;
    OSSL_PARAM params[2];
    char *temp_output_path = NULL;
    unsigned char *encrypted_chunk = NULL, *decrypted_chunk = NULL, *null_bytes = NULL;
    unsigned char enc_key[ENC_KEY_LENGTH], mac_key[MAC_KEY_LENGTH];
    int ret = EXIT_FAILURE;

    if(!confirm_overwrite(output_path)) return;

    f_in = fopen(input_path, "rb");
    if(!f_in){ perror("Errore nell'apertura del file di input"); goto cleanup; }
    
    temp_output_path = malloc(strlen(output_path) + 5);
    if(!temp_output_path){ fprintf(stderr, "Errore di allocazione memoria.\n"); goto cleanup; }
    sprintf(temp_output_path, "%s.tmp", output_path);
    
    f_out = fopen(temp_output_path, "wb");
    if(!f_out){ perror("Errore nella creazione del file temporaneo"); goto cleanup; }

    encrypted_chunk = malloc(CHUNK_SIZE);
    decrypted_chunk = malloc(CHUNK_SIZE);
    null_bytes = calloc(CHUNK_SIZE, 1);
    if(!encrypted_chunk || !decrypted_chunk || !null_bytes){ fprintf(stderr, "Errore di allocazione della memoria.\n"); goto cleanup; }
    
    unsigned char salt[SALT_LENGTH], nonce[NONCE_LENGTH], tag_from_file[TAG_LENGTH];
    if(fread(salt, 1, sizeof(salt), f_in) != sizeof(salt))
        goto format_error;
    if(fread(nonce, 1, sizeof(nonce), f_in) != sizeof(nonce))
        goto format_error;
    
    long ciphertext_start_pos = ftell(f_in);
    fseek(f_in, -TAG_LENGTH, SEEK_END);
    if(fread(tag_from_file, 1, sizeof(tag_from_file), f_in) != sizeof(tag_from_file))
        goto format_error;
    long ciphertext_end_pos = ftell(f_in) - TAG_LENGTH;
    long long ciphertext_size = ciphertext_end_pos - ciphertext_start_pos;
    fseek(f_in, ciphertext_start_pos, SEEK_SET);

    if(ciphertext_size < 0)
        goto format_error;
    if(!derive_keys(password, salt, enc_key, mac_key))
        goto cleanup;
    
    // blocco verifica HMAC moderno contro i warning
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if(!mac) handle_openssl_errors();

    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    
    mac_ctx = EVP_MAC_CTX_new(mac);
    if(!mac_ctx || !EVP_MAC_init(mac_ctx, mac_key, sizeof(mac_key), params)) handle_openssl_errors();
    if(!EVP_MAC_update(mac_ctx, salt, sizeof(salt))) handle_openssl_errors();
    if(!EVP_MAC_update(mac_ctx, nonce, sizeof(nonce))) handle_openssl_errors();

    long long bytes_to_verify = ciphertext_size;
    while(bytes_to_verify > 0){
        size_t chunk_to_read = (bytes_to_verify > CHUNK_SIZE) ? CHUNK_SIZE : (size_t)bytes_to_verify;
        size_t bytes_read = fread(encrypted_chunk, 1, chunk_to_read, f_in);
        
        if(bytes_read > 0){
            if(!EVP_MAC_update(mac_ctx, encrypted_chunk, bytes_read))
                handle_openssl_errors();
        }
        
        if(bytes_read != chunk_to_read)
            break;
        bytes_to_verify -= bytes_read;
    }
    
    unsigned char expected_tag[TAG_LENGTH];
    if(!EVP_MAC_final(mac_ctx, expected_tag, NULL, sizeof(expected_tag))) handle_openssl_errors();
    // fine blocco verifica HMAC

    if(CRYPTO_memcmp(tag_from_file, expected_tag, TAG_LENGTH) != 0){
        fprintf(stderr, "\nERRORE CRITICO: Il messaggio non è autentico! La password è errata o il file è stato manomesso.\n");
        goto cleanup;
    }

    printf("Autenticità verificata. Inizio decifratura...\n");
    fseek(f_in, ciphertext_start_pos, SEEK_SET);
    
    cipher_ctx = EVP_CIPHER_CTX_new();
    if(!cipher_ctx || !EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL, enc_key, nonce)) handle_openssl_errors();

    long long bytes_processed = 0;
    int len;
    
    while(bytes_processed < ciphertext_size){
        size_t chunk_to_read = ((ciphertext_size - bytes_processed) > CHUNK_SIZE) ? CHUNK_SIZE : (size_t)(ciphertext_size - bytes_processed);
        size_t bytes_read = fread(encrypted_chunk, 1, chunk_to_read, f_in);
        
        if(bytes_read > 0){
            unsigned char keystream_chunk[bytes_read];
            if(!EVP_DecryptUpdate(cipher_ctx, keystream_chunk, &len, null_bytes, bytes_read)) handle_openssl_errors();
            
            for(size_t i = 0; i < bytes_read; ++i) decrypted_chunk[i] = encrypted_chunk[i] ^ keystream_chunk[i];
            
            if(fwrite(decrypted_chunk, 1, bytes_read, f_out) != bytes_read){ perror("\nErrore di scrittura sul file temporaneo"); goto cleanup; }
        }
        
        if(bytes_read != chunk_to_read)
            break;
        bytes_processed += bytes_read;
        show_progress(bytes_processed, ciphertext_size, "Decifratura in corso");
    }
    
    if(ciphertext_size == 0) show_progress(0,0,"Decifratura in corso");
    printf("\n");

    fclose(f_out); f_out = NULL;
    if(rename(temp_output_path, output_path) != 0){ perror("Errore durante la rinomina del file temporaneo"); goto cleanup; }
    
    printf("File '%s' decifrato con successo in '%s'.\n", input_path, output_path);
    ret = EXIT_SUCCESS;
    goto cleanup;

// laber per GOTO; criticato ma utile
format_error:
    fprintf(stderr, "Errore: Formato del file di input non valido o file corrotto.\n");

cleanup:
    if(f_in) fclose(f_in);
    if(f_out) fclose(f_out);
    if(cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);
    if(mac_ctx) EVP_MAC_CTX_free(mac_ctx);
    if(mac) EVP_MAC_free(mac);
    if(ret == EXIT_FAILURE && temp_output_path) remove(temp_output_path);
    free(temp_output_path);
    free(encrypted_chunk);
    free(decrypted_chunk);
    free(null_bytes);
    OPENSSL_cleanse(enc_key, sizeof(enc_key));
    OPENSSL_cleanse(mac_key, sizeof(mac_key));
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

int confirm_overwrite(const char *filepath) {
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


/*** MAIN INTERATTIVO ****/
void main_interactive(){
    char choice[4];
    char input_file[256], output_file[256];
    char password[256], password_confirm[256];
    
    printf("*** OneTimeXOR: Cifratura File Sicura ***\n");
    
    while(1){
        printf("\nVuoi (C)ifrare o (D)ecifrare un file? (Q per uscire): ");
        if(!fgets(choice, sizeof(choice), stdin)) break;
        if(choice[0] == 'q' || choice[0] == 'Q') break;
        if(choice[0] == 'c' || choice[0] == 'C' || choice[0] == 'd' || choice[0] == 'D'){
            printf("Percorso del file di input: ");
            if(!fgets(input_file, sizeof(input_file), stdin)) break;
            input_file[strcspn(input_file, "\n")] = 0;
            printf("Percorso del file di output: ");
            if(!fgets(output_file, sizeof(output_file), stdin)) break;
            output_file[strcspn(output_file, "\n")] = 0;
            if(get_password("Inserisci la password: ", password, sizeof(password)) != 0 || strlen(password) == 0){
                 fprintf(stderr, "La password non può essere vuota.\n");
                 continue;
            }
            
            if(choice[0] == 'c' || choice[0] == 'C'){
                if(get_password("Reinserisci la password per conferma: ", password_confirm, sizeof(password_confirm)) != 0) continue;
                if(strcmp(password, password_confirm) != 0){
                    fprintf(stderr, "Le password non coincidono. Operazione annullata.\n");
                    continue;
                }
            }
            
            if(choice[0] == 'c' || choice[0] == 'C')
                encrypt_file(input_file, output_file, password);
            else
                decrypt_file(input_file, output_file, password);
        }else{
            printf("Scelta non valida. Riprova.\n");
        }
        
        OPENSSL_cleanse(password, sizeof(password));
        OPENSSL_cleanse(password_confirm, sizeof(password_confirm));
        printf("----------------------------------------------------\n");
    }
}

/*** MAIN RIGA DI COMANDO ****/
void main_cli(int argc, char *argv[]){
    char *input_file = NULL, *output_file = NULL;
    char password[256], password_confirm[256];
    const char *command = NULL;
    
    if(argc != 6){ fprintf(stderr, "Uso: %s <encrypt|decrypt> -i <input> -o <output>\n", argv[0]); return; }
    command = argv[1];
    
    for(int i = 2; i < argc; i += 2){
        if (strcmp(argv[i], "-i") == 0) input_file = argv[i+1];
        else if (strcmp(argv[i], "-o") == 0) output_file = argv[i+1];
    }
    
    if(!input_file || !output_file){ fprintf(stderr, "Uso: %s <encrypt|decrypt> -i <input> -o <output>\n", argv[0]); return; }
    if(get_password("Inserisci la password: ", password, sizeof(password)) != 0 || strlen(password) == 0){
        fprintf(stderr, "La password non può essere vuota.\n");
        return;
    }
    if(strcmp(command, "encrypt") == 0){
        if(get_password("Reinserisci la password per conferma: ", password_confirm, sizeof(password_confirm)) != 0) return;
        if(strcmp(password, password_confirm) != 0){ fprintf(stderr, "Le password non coincidono. Operazione annullata.\n"); return; }
        encrypt_file(input_file, output_file, password);
    }else if(strcmp(command, "decrypt") == 0){
        decrypt_file(input_file, output_file, password);
    }else{
        fprintf(stderr, "Comando sconosciuto: %s\n", command);
    }
    
    OPENSSL_cleanse(password, sizeof(password));
    OPENSSL_cleanse(password_confirm, sizeof(password_confirm));
}


/*** MAIN ****/
int main(int argc, char *argv[]){
    OPENSSL_init_crypto(0, NULL);
    
    if (argc > 1)
        main_cli(argc, argv);
    else
        main_interactive();
    
    return 0;
}

