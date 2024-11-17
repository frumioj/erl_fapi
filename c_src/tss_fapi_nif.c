#include <erl_nif.h>
#include <tss2/tss2_fapi.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#include "tss_fapi_nif.h"

//static ErlNifResourceType* FAPI_CONTEXT_RESOURCE;

#define PATH_MAX 4096

// Helper functions
static ERL_NIF_TERM make_error(ErlNifEnv* env, TSS2_RC rc) {
    return enif_make_tuple2(env, 
        enif_make_atom(env, "error"),
        enif_make_int(env, rc));
}

static ERL_NIF_TERM make_ok(ErlNifEnv* env) {
    return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM make_ok_with_binary(ErlNifEnv* env, const uint8_t* data, size_t length) {
    ERL_NIF_TERM binary;
    unsigned char* buf = enif_make_new_binary(env, length, &binary);
    memcpy(buf, data, length);
    return enif_make_tuple2(env, 
        enif_make_atom(env, "ok"),
        binary);
}

// Change the return type from int to ERL_NIF_TERM
static ERL_NIF_TERM
initialize(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    FAPI_CONTEXT *fapi_context = NULL;
    TSS2_RC rc;
    
    // Create user-specific directories
    char *home = getenv("HOME");
    if (!home) {
        return enif_make_tuple2(env, 
                              enif_make_atom(env, "error"),
                              enif_make_atom(env, "no_home_directory"));
    }

    char keystore_path[PATH_MAX];
    char log_path[PATH_MAX];
    
    snprintf(keystore_path, sizeof(keystore_path), "%s/.local/share/tpm2-tss/", home);
    snprintf(log_path, sizeof(log_path), "%s/.local/share/tpm2-tss/logs/", home);
    
    // Create directories
    if (mkdir(keystore_path, 0700) != 0 && errno != EEXIST) {
        return enif_make_tuple2(env, 
                              enif_make_atom(env, "error"),
                              enif_make_tuple2(env,
                                             enif_make_atom(env, "mkdir_failed"),
                                             enif_make_string(env, strerror(errno), ERL_NIF_LATIN1)));
    }

    if (mkdir(log_path, 0700) != 0 && errno != EEXIST) {
        return enif_make_tuple2(env, 
                              enif_make_atom(env, "error"),
                              enif_make_tuple2(env,
                                             enif_make_atom(env, "mkdir_failed"),
                                             enif_make_string(env, strerror(errno), ERL_NIF_LATIN1)));
    }
    
    // Create FAPI config
    char config_path[PATH_MAX];
    snprintf(config_path, sizeof(config_path), "%s/.local/share/tpm2-tss/fapi-config.json", home);
    
    FILE *f = fopen(config_path, "w");
    if (!f) {
        return enif_make_tuple2(env, 
                              enif_make_atom(env, "error"),
                              enif_make_tuple2(env,
                                             enif_make_atom(env, "config_create_failed"),
                                             enif_make_string(env, strerror(errno), ERL_NIF_LATIN1)));
    }

    fprintf(f, "{\n"
              "  \"profile_name\": \"P_ECCP256SHA256\",\n"
              "  \"profile_dir\": \"%s/.local/share/tpm2-tss/\",\n"
              "  \"user_dir\": \"%s/.local/share/tpm2-tss/user/\",\n"
              "  \"system_dir\": \"%s/.local/share/tpm2-tss/system/\",\n"
              "  \"log_dir\": \"%s/.local/share/tpm2-tss/logs/\",\n"
              "  \"tcti\": \"device:/dev/tpmrm0\"\n"
              "}\n", home, home, home, home);
    fclose(f);

    // Initialize FAPI with custom config
    rc = Fapi_Initialize(&fapi_context, config_path);
    
    if (rc != TSS2_RC_SUCCESS) {
        return enif_make_tuple2(env, 
                              enif_make_atom(env, "error"),
                              enif_make_uint(env, rc));
    }

    // Create resource for the context
    FAPI_CONTEXT** ctx_resource = enif_alloc_resource(FAPI_CONTEXT_RESOURCE, sizeof(FAPI_CONTEXT*));
    if (!ctx_resource) {
        Fapi_Finalize(&fapi_context);
        return enif_make_tuple2(env, 
                              enif_make_atom(env, "error"),
                              enif_make_atom(env, "out_of_memory"));
    }

    *ctx_resource = fapi_context;
    ERL_NIF_TERM result = enif_make_resource(env, ctx_resource);
    enif_release_resource(ctx_resource);

    return enif_make_tuple2(env, 
                           enif_make_atom(env, "ok"),
                           result);
}

/* static ERL_NIF_TERM initialize(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { */
/*     FAPI_CONTEXT* fapi_context = NULL;  // Initialize to NULL */
/*     TSS2_RC rc; */
    
/*     // Allocate the resource after successful initialization */
/*     rc = Fapi_Initialize(&fapi_context, NULL); */
    
/*     if (rc != TSS2_RC_SUCCESS) { */
/*         return make_error(env, rc); */
/*     } */

/*     // Now allocate the resource and copy the context */
/*     FAPI_CONTEXT** ctx_resource = enif_alloc_resource(FAPI_CONTEXT_RESOURCE, sizeof(FAPI_CONTEXT*)); */
/*     if (!ctx_resource) { */
/*         Fapi_Finalize(&fapi_context); */
/*         return make_error(env, TSS2_FAPI_RC_MEMORY); */
/*     } */

/*     *ctx_resource = fapi_context; */

/*     ERL_NIF_TERM result = enif_make_resource(env, ctx_resource); */
/*     enif_release_resource(ctx_resource); */
/*     return enif_make_tuple2(env, enif_make_atom(env, "ok"), result); */
/* } */

// Provision TPM
static ERL_NIF_TERM provision(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    FAPI_CONTEXT* fapi_context;
    
    if (!enif_get_resource(env, argv[0], FAPI_CONTEXT_RESOURCE, (void**)&fapi_context))
        return enif_make_badarg(env);

    TSS2_RC rc = Fapi_Provision(fapi_context, NULL, NULL, NULL);
    
    if (rc != TSS2_RC_SUCCESS)
        return make_error(env, rc);
    
    return make_ok(env);
}

// Get random bytes
static ERL_NIF_TERM get_random(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    FAPI_CONTEXT* fapi_context;
    uint32_t num_bytes;
    uint8_t* data;
    
    if (!enif_get_resource(env, argv[0], FAPI_CONTEXT_RESOURCE, (void**)&fapi_context) ||
        !enif_get_uint(env, argv[1], &num_bytes))
        return enif_make_badarg(env);

    data = (uint8_t*)malloc(num_bytes);
    if (!data)
        return make_error(env, TSS2_FAPI_RC_MEMORY);

    TSS2_RC rc = Fapi_GetRandom(fapi_context, num_bytes, &data);
    
    if (rc != TSS2_RC_SUCCESS) {
        free(data);
        return make_error(env, rc);
    }

    ERL_NIF_TERM result = make_ok_with_binary(env, data, num_bytes);
    free(data);
    return result;
}

// Create key
static ERL_NIF_TERM create_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    FAPI_CONTEXT* fapi_context;
    char key_path[256];
    char type[64];
    
    if (!enif_get_resource(env, argv[0], FAPI_CONTEXT_RESOURCE, (void**)&fapi_context) ||
        !enif_get_string(env, argv[1], key_path, sizeof(key_path), ERL_NIF_LATIN1) ||
        !enif_get_string(env, argv[2], type, sizeof(type), ERL_NIF_LATIN1))
        return enif_make_badarg(env);

    char* policy = "";  // Empty policy for now
    TSS2_RC rc = Fapi_CreateKey(fapi_context, key_path, type, policy, NULL);
    
    if (rc != TSS2_RC_SUCCESS)
        return make_error(env, rc);
    
    return make_ok(env);
}

// Verify signature
static ERL_NIF_TERM verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    FAPI_CONTEXT* fapi_context;
    char key_path[256];
    ErlNifBinary data;
    ErlNifBinary signature;
    char scheme[64];
    
    if (!enif_get_resource(env, argv[0], FAPI_CONTEXT_RESOURCE, (void**)&fapi_context) ||
        !enif_get_string(env, argv[1], key_path, sizeof(key_path), ERL_NIF_LATIN1) ||
        !enif_inspect_binary(env, argv[2], &data) ||
        !enif_inspect_binary(env, argv[3], &signature) ||
        !enif_get_string(env, argv[4], scheme, sizeof(scheme), ERL_NIF_LATIN1))
        return enif_make_badarg(env);

    TSS2_RC rc = Fapi_VerifySignature(fapi_context, key_path,
                                     signature.data, signature.size,
                                     data.data, data.size);
    
    if (rc != TSS2_RC_SUCCESS)
        return make_error(env, rc);
    
    return make_ok(env);
}

// Encrypt data
static ERL_NIF_TERM encrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    FAPI_CONTEXT* fapi_context;
    char key_path[256];
    ErlNifBinary data;
    char scheme[64];
    uint8_t* encrypted = NULL;
    size_t encrypted_size;
    
    if (!enif_get_resource(env, argv[0], FAPI_CONTEXT_RESOURCE, (void**)&fapi_context) ||
        !enif_get_string(env, argv[1], key_path, sizeof(key_path), ERL_NIF_LATIN1) ||
        !enif_inspect_binary(env, argv[2], &data) ||
        !enif_get_string(env, argv[3], scheme, sizeof(scheme), ERL_NIF_LATIN1))
        return enif_make_badarg(env);

    TSS2_RC rc = Fapi_Encrypt(fapi_context, key_path,
                             data.data, data.size,
                             &encrypted, &encrypted_size);
    
    if (rc != TSS2_RC_SUCCESS)
        return make_error(env, rc);

    ERL_NIF_TERM result = make_ok_with_binary(env, encrypted, encrypted_size);
    free(encrypted);
    return result;
}

// Decrypt data
static ERL_NIF_TERM decrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    FAPI_CONTEXT* fapi_context;
    char key_path[256];
    ErlNifBinary encrypted_data;
    char scheme[64];
    uint8_t* decrypted = NULL;
    size_t decrypted_size;
    
    if (!enif_get_resource(env, argv[0], FAPI_CONTEXT_RESOURCE, (void**)&fapi_context) ||
        !enif_get_string(env, argv[1], key_path, sizeof(key_path), ERL_NIF_LATIN1) ||
        !enif_inspect_binary(env, argv[2], &encrypted_data) ||
        !enif_get_string(env, argv[3], scheme, sizeof(scheme), ERL_NIF_LATIN1))
        return enif_make_badarg(env);

    TSS2_RC rc = Fapi_Decrypt(fapi_context, key_path,
                             encrypted_data.data, encrypted_data.size,
                             &decrypted, &decrypted_size);
    
    if (rc != TSS2_RC_SUCCESS)
        return make_error(env, rc);

    ERL_NIF_TERM result = make_ok_with_binary(env, decrypted, decrypted_size);
    free(decrypted);
    return result;
}

// Sign data
static ERL_NIF_TERM sign(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    FAPI_CONTEXT* fapi_context;
    char key_path[256];
    ErlNifBinary data;
    char scheme[64];
    uint8_t* signature = NULL;
    size_t signature_size;
    
    if (!enif_get_resource(env, argv[0], FAPI_CONTEXT_RESOURCE, (void**)&fapi_context) ||
        !enif_get_string(env, argv[1], key_path, sizeof(key_path), ERL_NIF_LATIN1) ||
        !enif_inspect_binary(env, argv[2], &data) ||
        !enif_get_string(env, argv[3], scheme, sizeof(scheme), ERL_NIF_LATIN1))
        return enif_make_badarg(env);

    TSS2_RC rc = Fapi_Sign(fapi_context, key_path, scheme,
                          data.data, data.size,
                          &signature, &signature_size, NULL, NULL);
    
    if (rc != TSS2_RC_SUCCESS)
        return make_error(env, rc);

    ERL_NIF_TERM result = make_ok_with_binary(env, signature, signature_size);
    free(signature);
    return result;
}

// Cleanup function for FAPI context
static void fapi_context_destructor(ErlNifEnv* env, void* obj) {
    FAPI_CONTEXT** ctx = (FAPI_CONTEXT**)obj;
    if (ctx && *ctx) {
        Fapi_Finalize(ctx);
    }
}

// Module initialization
static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {
    int flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;
    FAPI_CONTEXT_RESOURCE = enif_open_resource_type(env, NULL,
        "fapi_context_resource", fapi_context_destructor, flags, NULL);
    
    if (FAPI_CONTEXT_RESOURCE == NULL)
        return -1;
    
    return 0;
}

static ErlNifFunc nif_funcs[] = {
    {"initialize", 0, initialize, 0},
    {"provision", 1, provision, 0},
    {"get_random", 2, get_random, 0},
    {"create_key", 3, create_key, 0},
    {"sign", 4, sign, 0},
    {"verify", 5, verify, 0},
    {"encrypt", 4, encrypt, 0},
    {"decrypt", 4, decrypt, 0}
};

ERL_NIF_INIT(tss_fapi_nif, nif_funcs, load, NULL, NULL, NULL)
