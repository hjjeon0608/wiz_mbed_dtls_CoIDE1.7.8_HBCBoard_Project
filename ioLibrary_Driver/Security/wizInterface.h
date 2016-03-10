 /*
 * file: SSL_Interface.h
 * description: wiznet network interface for mbedtls
 * author: peter
 * company: wiznet
 * data: on development
 */

#ifndef _WIZINTERFACE_H_
#define _WIZINTERFACE_H_

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/compat-1.3.h"
#include "mbedtls/debug.h"
#include <stdlib.h>

#define wiz_mbedtls_ssl_write				mbedtls_ssl_write
#define wiz_mbedtls_ssl_read				mbedtls_ssl_read
#define wiz_mbedtls_ssl_socket				socket
#define wiz_mbedtls_ssl_close_notify		mbedtls_ssl_close_notify
#define wiz_mbedtls_ssl_close				close

/*
 * Macro definition
 */
      
#define DEBUG_LEVEL						3

#define WIZ_RECV_TIMEOUT_VALUE			10000
   
/*
 * Call Back function registration
 */
#define SSLSendCB 			WIZnetSend
#define SSLRecvCB 			WIZnetRecv
#define SSLRecvTimeOutCB		WIZnetRecvTimeOut
#define SSLFSetTimerCB			WIZnetSetTimer
#define SSLFGetTimerCB			WIZnetGetTimer

#define WIZ_ERR_CONNECT_TIMEOUT		-0x9000
   
typedef struct{
	mbedtls_entropy_context* entropy;
	mbedtls_ctr_drbg_context* ctr_drbg;
	mbedtls_ssl_context* ssl;
	mbedtls_ssl_config* conf;
	mbedtls_x509_crt* cacert;
}wiz_ssl_context;

void WIZnetSetTimer(void *pTimer, uint32_t iTimeOut, uint32_t fTimeOut);

int WIZnetGetTimer(void *pTimer);

/*
 * name: WIZnetRecv
 * brief: WIZnet socket(recv) interface function for mbedTLS
 * param ctx: Context for callback(socket handler = w5500 socket number)
 * param buf: buffer
 * param len: number of bytes to read
 */
int WIZnetRecv(void *ctx, unsigned char *buf, unsigned int len );

/*
 * name: WIZnetRecvTimeOut
 * brief: WIZnet socket(recv) interface function for mbedTLS
 * param ctx: Context for callback(socket handler = w5500 socket number)
 * param buf: buffer
 * param len: number of bytes to read
 * param timeout: timeout value in millisecond
 */
int WIZnetRecvTimeOut(void *ctx, unsigned char *buf, unsigned int len, unsigned int timeout);

/*
 * name: WIZnetSend
 * brief: WIZnet socket(send) interface function for mbedTLS
 * param ctx: Context for callback(socket handler = w5500 socket number)
 * param buf: buffer
 * param len: number of bytes to write
 */
int WIZnetSend(void *ctx, const unsigned char *buf, unsigned int len );


/*
 * name: SSLDebugCB
 * brief: printf callback function for debug
 * param ctx: Context for callback - ignored
 * param level: debug level - 0/1/2/3(0 is no debug)
 * param file: file pointer - ignored
 * param line: - ignored
 * param str: debug message pointer
 */
void SSLDebugCB(void *ctx, int level, const char *file, int line, const char *str);

int SSLRandomCB( void *p_rng, unsigned char *output, size_t output_len );

/*
 * name: SSLInit
 * brief: Initialize SSL Contexts.
 * param sslContext: Structure of SSL Contexts
 * param SocketHandler: SocketHandler(w5500 socket number)
 */
unsigned char wiz_mbedtls_ssl_init(wiz_ssl_context* sslContext, uint8_t* SocketHandler);

/*
 * name: SSLDeinit
 * brief: Deinitialize SSL Contexts.
 * param sslContext: Structure of SSL Contexts
 */
void wiz_mbedtls_ssl_deinit(wiz_ssl_context* sslContext);

/*
 * name: SSLHandshake
 * brief: Perform the SSL handshake
 * param sslContext: Structure of SSL Contexts
 */
unsigned int wiz_mbedtls_ssl_handshake(wiz_ssl_context* sslContext);


#endif //_WIZINTERFACE_H_

