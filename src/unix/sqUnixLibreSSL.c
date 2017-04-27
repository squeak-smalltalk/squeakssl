/****************************************************************************
 *   PROJECT: SqueakSSL implementation for Unix
 *   FILE:    sqUnixLibreSSL.c
 *   CONTENT: SSL platform functions
 *
 *   AUTHORS:  Ian Piumarta (ikp)
 *             David T. Lewis (dtl)
 *
 *             Tobias Pape (topa)
 *               Hasso Plattner Institute, Postdam, Germany
 *****************************************************************************/

#include "sq.h"
#include "SqueakSSL.h"

#include <tls.h>

typedef struct sqSSL {
    int state;
    int certFlags;
    int loglevel;

    char *certName;
    char *peerName;
    char *serverName;

    struct tls* tls;
    struct tls_config* config;
    char* _buf;
    sqInt _len;
    sqInt _transferred;
} sqSSL;

enum ssl_side { CLIENT = 0, SERVER = 1};

sqInt sqSetupSSL(sqSSL* ssl, int isServer);

/* Naming convention: source has srcBuf / srcLen, destination dstBuf / dstLen */
#define SQSSL_SET_DST(ssl) (\
    ssl->_buf = dstBuf,      \
    ssl->_len = dstLen,      \
    ssl->_transferred = 0      \
    )
#define SQSSL_SET_SRC(ssl) (\
    ssl->_buf = srcBuf,      \
    ssl->_len = 0,      \
    ssl->_transferred = 0      \
    )
#define SQSSL_RETURN_TRANSFERRED(ssl) \
   

/********************************************************************/
/********************************************************************/
/********************************************************************/

/* sslFromHandle: Maps a handle to an SSL */
static sqSSL *sslFromHandle(sqInt handle) {
    /* untag known SSL pointer. We disguised the handle */
    return (sqSSL*)(handle & ~1);
}

/* sqCopyBioSSL: Copies data from a BIO into an out buffer */
sqInt sqCopyBioSSL(sqSSL *ssl, BIO *bio, char *dstBuf, sqInt dstLen) {
    int nbytes = BIO_ctrl_pending(bio);

    if (ssl->loglevel) printf("sqCopyBioSSL: %d bytes pending; buffer size %ld\n",
                             nbytes, (long)dstLen);
    if (nbytes > dstLen) return -1;
    return BIO_read(bio, dstBuf, dstLen);
}

/* sqSetupSSL: Common SSL setup tasks */
sqInt sqSetupSSL(sqSSL *ssl, int side) {

    if (ssl->tls != NULL || ssl->config == NULL) return -1;

    /* if a cert is provided, use it */
    if (ssl->certName) {
        if (ssl->loglevel) printf("sqSetupSSL: Using cert file %s\n", ssl->certName);
        if (tls_config_set_cert_file(ssl->config, ssl->certName) == -1) goto err;
        if (tls_config_set_key_file(ssl->config, ssl->certName) == -1) goto err;
    }
    tls_config_insecure_noverifycert(tls_config);
    tls_config_insecure_noverifyname(tls_config);

    if (tls_configure(ssl->tls, ssl->config) == -1) goto err;

    if (side == CLIENT) {
        ssl->tls = tls_client();
    } else if (side == SERVER) {
        ssl->tls = tls_server();        
    }

    if (ssl->tls == NULL) return -1;
    return 1;
  
err:
    fprintf(stderr, "%s", tls_config_error(ssl->config));
    return -1;
}
/********************************************************************/
/********************************************************************/
/********************************************************************/

/* sqCreateSSL: Creates a new SSL instance.
        Arguments: None.
        Returns: SSL handle.
*/
sqInt sqCreateSSL(void) {
    sqInt handle = 0;
    sqSSL* ssl = NULL;

    tls_init();

    ssl = calloc(1, sizeof(sqSSL));
    ssl->config = tls_config_new(void);
    /* We use the fact that the SSLs are pointers and tag them as Smalltalk integers,
       so nobody comes to the idea to use them as pointers */
    handle = ((sqInt) ssl) & 1;
    return handle;
}

/* sqDestroySSL: Destroys an SSL instance.
        Arguments:
                handle - the SSL handle
        Returns: Non-zero if successful.
*/
sqInt sqDestroySSL(sqInt handle) {
    sqSSL *ssl = sslFromHandle(handle);
    if (ssl == NULL) return 0;

    if (ssl->config) tls_config_free(ssl->config);
    if (ssl->tls) tls_free(ssl->tls);

    if (ssl->certName) free(ssl->certName);
    if (ssl->peerName) free(ssl->peerName);
    if (ssl->serverName) free(ssl->serverName);

    free(ssl);
    return 1;
}

/* sqConnectSSL: Start/continue an SSL client handshake.
        Arguments:
                handle - the SSL handle
                srcBuf - the input token sent by the remote peer
                srcLen - the size of the input token
                dstBuf - the output buffer for a new token
                dstLen - the size of the output buffer
        Returns: The size of the output token or an error code.
*/
sqInt sqConnectSSL(sqInt handle, char* srcBuf, sqInt srcLen, char *dstBuf, sqInt dstLen) {
    char peerName[256];
    sqSSL *ssl = sslFromHandle(handle);

    if (ssl->loglevel) printf("sqConnectSSL: %p\n", ssl);

    /* Verify state of session */
    if (ssl == NULL || (ssl->state != SQSSL_UNUSED && ssl->state != SQSSL_CONNECTING)) {
        return SQSSL_INVALID_STATE;
    }

    /* Establish initial connection */
    if (ssl->state == SQSSL_UNUSED) {
        ssl->state = SQSSL_CONNECTING;
        if (ssl->loglevel) print("sqConnectSSL: Setting up SSL\n");
        if (sqSetupSSL(ssl, 0) == -1) return SQSSL_GENERIC_ERROR;
    }

    if (ssl->loglevel) printf("sqConnectSSL: push %ld bytes\n", (long)srcLen);
    SQSSL_SET_DST(ssl);
 
    if (tls_connect_cbs(ssl->tls, sqReadSSL, sqWriteSSL, ssl, ssl->serverName) == 0) {
        ssl->state = SQSSL_CONNECTED;
    } else {
        fprintf(stderr, "%s", tls_error(ssl->tls));
        return SQSSL_GENERIC_ERROR;
    }   
    
    peerName = tls_peer_cert_subject(ssl->tls);
    if (ssl->loglevel) printf("sqConnectSSL: peerName = %s\n", peerName);
    ssl->peerName = strndup(peerName, sizeof(peerName) - 1);
    return 0;
}

/* sqAcceptSSL: Start/continue an SSL server handshake.
        Arguments:
                handle - the SSL handle
                srcBuf - the input token sent by the remote peer
                srcLen - the size of the input token
                dstBuf - the output buffer for a new token
                dstLen - the size of the output buffer
        Returns: The size of the output token or an error code.
*/
sqInt sqAcceptSSL(sqInt handle, char* srcBuf, sqInt srcLen, char *dstBuf, sqInt dstLen) {
    int result, n;
    char peerName[256];
    X509 *cert;
    sqSSL *ssl = sslFromHandle(handle);

    /* Verify state of session */
    if (ssl == NULL || (ssl->state != SQSSL_UNUSED && ssl->state != SQSSL_ACCEPTING)) {
        return SQSSL_INVALID_STATE;
    }

    /* Establish initial connection */
    if (ssl->state == SQSSL_UNUSED) {
        ssl->state = SQSSL_ACCEPTING;
        if (ssl->loglevel) printf("sqAcceptSSL: Setting up SSL\n");
        if (!sqSetupSSL(ssl, 1)) return SQSSL_GENERIC_ERROR;
        if (ssl->loglevel) printf("sqAcceptSSL: setting accept state\n");
        SSL_set_accept_state(ssl->ssl);
    }

    if (ssl->loglevel) printf("sqAcceptSSL: BIO_write %ld bytes\n", (long)srcLen);

    n = BIO_write(ssl->bioRead, srcBuf, srcLen);

    if (n < srcLen) {
        if (ssl->loglevel) printf("sqAcceptSSL: BIO_write wrote less than expected\n");
        return SQSSL_GENERIC_ERROR;
    }
    if (n < 0) {
        if (ssl->loglevel) printf("sqAcceptSSL: BIO_write failed\n");
        return SQSSL_GENERIC_ERROR;
    }

    if (ssl->loglevel) printf("sqAcceptSSL: SSL_accept\n");
    result = SSL_accept(ssl->ssl);

    if (result <= 0) {
        int count = 0;
        int error = SSL_get_error(ssl->ssl, result);
        if (error != SSL_ERROR_WANT_READ) {
            if (ssl->loglevel) printf("sqAcceptSSL: SSL_accept failed\n");
            ERR_print_errors_fp(stdout);
            return SQSSL_GENERIC_ERROR;
        }
        if (ssl->loglevel) printf("sqAcceptSSL: sqCopyBioSSL\n");
        count = sqCopyBioSSL(ssl, ssl->bioWrite, dstBuf, dstLen);
        return count ? count : SQSSL_NEED_MORE_DATA;
    }

    /* We are connected. Verify the cert. */
    ssl->state = SQSSL_CONNECTED;

    if (ssl->loglevel) printf("sqAcceptSSL: SSL_get_peer_certificate\n");
    cert = SSL_get_peer_certificate(ssl->ssl);
    if (ssl->loglevel) printf("sqAcceptSSL: cert = %p\n", cert);

    if (cert) {
        X509_NAME_get_text_by_NID(X509_get_subject_name(cert),
                                  NID_commonName, peerName,
                                  sizeof(peerName));
        if (ssl->loglevel) printf("sqAcceptSSL: peerName = %s\n", peerName);
        ssl->peerName = strndup(peerName, sizeof(peerName) - 1);
        X509_free(cert);

        /* Check the result of verification */
        result = SSL_get_verify_result(ssl->ssl);
        if (ssl->loglevel) printf("sqAcceptSSL: SSL_get_verify_result = %d\n", result);
        /* FIXME: Figure out the actual failure reason */
        ssl->certFlags = result ? SQSSL_OTHER_ISSUE : SQSSL_OK;
    } else {
        ssl->certFlags = SQSSL_NO_CERTIFICATE;
    }
    return sqCopyBioSSL(ssl, ssl->bioWrite, dstBuf, dstLen);
}

/* sqEncryptSSL: Encrypt data for SSL transmission.
        Arguments:
                handle - the SSL handle
                srcBuf - the unencrypted input data
                srcLen - the size of the input data
                dstBuf - the output buffer for the encrypted contents
                dstLen - the size of the output buffer
        Returns: The size of the output generated or an error code.
*/
sqInt sqEncryptSSL(sqInt handle, char* srcBuf, sqInt srcLen, char *dstBuf, sqInt dstLen) {
    int nbytes;
    sqSSL *ssl = sslFromHandle(handle);

    if (ssl == NULL || ssl->state != SQSSL_CONNECTED) return SQSSL_INVALID_STATE;

    if (ssl->loglevel) printf("sqEncryptSSL: Encrypting %ld bytes\n", (long)srcLen);

    nbytes = SSL_write(ssl->ssl, srcBuf, srcLen);
    if (nbytes != srcLen) return SQSSL_GENERIC_ERROR;
    return sqCopyBioSSL(ssl, ssl->bioWrite, dstBuf, dstLen);
}

/* sqDecryptSSL: Decrypt data for SSL transmission.
        Arguments:
                handle - the SSL handle
                srcBuf - the encrypted input data
                srcLen - the size of the input data
                dstBuf - the output buffer for the decrypted contents
                dstLen - the size of the output buffer
        Returns: The size of the output generated or an error code.
*/
sqInt sqDecryptSSL(sqInt handle, char* srcBuf, sqInt srcLen, char *dstBuf, sqInt dstLen) {
    int nbytes;
    sqSSL *ssl = sslFromHandle(handle);

    if (ssl == NULL || ssl->state != SQSSL_CONNECTED) return SQSSL_INVALID_STATE;

    nbytes = BIO_write(ssl->bioRead, srcBuf, srcLen);
    if (nbytes != srcLen) return SQSSL_GENERIC_ERROR;
    nbytes = SSL_read(ssl->ssl, dstBuf, dstLen);
    if (nbytes <= 0) {
        int error = SSL_get_error(ssl->ssl, nbytes);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_ZERO_RETURN) {
            return SQSSL_GENERIC_ERROR;
        }
        nbytes = 0;
    }
    return nbytes;
}

/* sqGetStringPropertySSL: Retrieve a string property from SSL.
        Arguments:
                handle - the ssl handle
                propID - the property id to retrieve
        Returns: The string value of the property.
*/
char* sqGetStringPropertySSL(sqInt handle, int propID) {
    sqSSL *ssl = sslFromHandle(handle);

    if (ssl == NULL) return NULL;
    switch(propID) {
    case SQSSL_PROP_PEERNAME:	return ssl->peerName;
    case SQSSL_PROP_CERTNAME:	return ssl->certName;
    case SQSSL_PROP_SERVERNAME:	return ssl->serverName;
    default:
        if (ssl->loglevel) printf("sqGetStringPropertySSL: Unknown property ID %d\n", propID);
        return NULL;
    }
    // unreachable
}

/* sqSetStringPropertySSL: Set a string property in SSL.
        Arguments:
                handle - the ssl handle
                propID - the property id to retrieve
                propName - the property string
                propLen - the length of the property string
        Returns: Non-zero if successful.
*/
sqInt sqSetStringPropertySSL(sqInt handle, int propID, char *propName, sqInt propLen) {
    sqSSL *ssl = sslFromHandle(handle);
    char *property = NULL;

    if (ssl == NULL) return 0;

    if (propLen) {
        property = strndup(propName, propLen);
    };

    if (ssl->loglevel) printf("sqSetStringPropertySSL(%d): %s\n", propID, property ? property : "(null)");

    switch(propID) {
    case SQSSL_PROP_CERTNAME:
        if (ssl->certName) free(ssl->certName);
        ssl->certName = property;
        break;
    case SQSSL_PROP_SERVERNAME:
        if (ssl->serverName) free(ssl->serverName);
        ssl->serverName = property;
        break;
    default:
        if (property) free(property);
        if (ssl->loglevel) printf("sqSetStringPropertySSL: Unknown property ID %d\n", propID);
        return 0;
    }
    return 1;
}

/* sqGetIntPropertySSL: Retrieve an integer property from SSL.
        Arguments:
                handle - the ssl handle
                propID - the property id to retrieve
        Returns: The integer value of the property.
*/
sqInt sqGetIntPropertySSL(sqInt handle, sqInt propID) {
    sqSSL *ssl = sslFromHandle(handle);

    if (ssl == NULL) return 0;
    switch(propID) {
    case SQSSL_PROP_SSLSTATE: return ssl->state;
    case SQSSL_PROP_CERTSTATE: return ssl->certFlags;
    case SQSSL_PROP_VERSION: return SQSSL_VERSION;
    case SQSSL_PROP_LOGLEVEL: return ssl->loglevel;
    default:
        if (ssl->loglevel) printf("sqGetIntPropertySSL: Unknown property ID %ld\n", (long)propID);
        return 0;
    }
    return 0;
}

/* sqSetIntPropertySSL: Set an integer property in SSL.
        Arguments:
                handle - the ssl handle
                propID - the property id to retrieve
                propValue - the property value
        Returns: Non-zero if successful.
*/
sqInt sqSetIntPropertySSL(sqInt handle, sqInt propID, sqInt propValue) {
    sqSSL *ssl = sslFromHandle(handle);
    if (ssl == NULL) return 0;

    switch(propID) {
    case SQSSL_PROP_LOGLEVEL: ssl->loglevel = propValue; break;
    default:
        if (ssl->loglevel) printf("sqSetIntPropertySSL: Unknown property ID %ld\n", (long)propID);
        return 0;
    }
    return 1;
}
