/*
 * file: SSL_Interface.c
 * description: mbedtls callback functions
 * author: peter
 * company: wiznet
 * data: 2015.11.26
 */

#include "wizInterface.h"
#include "socket.h"
#include "certificate.h"
#include "mbedtls/debug.h"
#include <stdio.h>

static uint32_t (*getTick)(void);

static uint32_t TimerReference;
static uint32_t fTimeOutValue;
static uint32_t iTimeOutValue;

void WIZnetRegFuncTicker(uint32_t (*tickerCB)(void))
{
	getTick = tickerCB;
}
/*
 * \param p_timer  parameter (context) shared by timer callback
 * \param f_set_timer   set timer callback
 *                 Accepts an intermediate and a final delay in milliseconcs
 *                 If the final delay is 0, cancels the running timer.
 * \param f_get_timer   get timer callback. Must return:
 *                 -1 if cancelled
 *                 0 if none of the delays is expired
 *                 1 if the intermediate delay only is expired
 *                 2 if the final delay is expired
 */
void WIZnetSetTimer(void *pTimer, uint32_t iTimeOut, uint32_t fTimeOut)
{
	if(!fTimeOut)
	{
		fTimeOutValue = 0;
		fTimeOutValue = 0;
		iTimeOutValue = 0;
	}
	else
	{
		TimerReference = getTick();
		fTimeOutValue = fTimeOut;
		iTimeOutValue = iTimeOut;
	}
}
int WIZnetGetTimer(void *pTimer)
{
  	uint32_t CurrentTick = getTick();
	uint8_t TimerExpired = (((CurrentTick-TimerReference) > fTimeOutValue)?2:0)|(((CurrentTick-TimerReference) > iTimeOutValue)?1:0);
	if(fTimeOutValue == 0) return -1;
	switch(TimerExpired)
	{
	case 0://There is no timer expired.
	  return 0;
	  break;
	case 1://Only iTimer is Expired.
	  return 1;
	  break;
	case 2://Only fTimer is Expired. --> Error
	  iTimeOutValue = 0;
	  fTimeOutValue = 0;
	  return -1;
	  break;
	case 3://iTimer and fTimer is expired.
	  return 2;
	  break;
	default:
	  return -1;
	}
}

int WIZnetSend(void *ctx, const unsigned char *buf, unsigned int len )
{
	while(getSn_TX_FSR(*((int *)ctx)) < len && len < getSn_TxMAX(*((int *)ctx))){};
	return send(*((int *)ctx),(uint8_t*)buf,len);
}

int WIZnetRecv(void *ctx, unsigned char *buf, unsigned int len )
{
      return (recv(*((int *)ctx),buf,len));
}

int WIZnetRecvTimeOut(void *ctx, unsigned char *buf, unsigned int len, unsigned int timeout)
{
	uint32_t startTick = getTick();
	unsigned int ret;
	do
	{
		if(getSn_RX_RSR(*((int *)ctx))){
			return recv(*((int *)ctx),buf,len);
		}
	}while((getTick() - startTick) <= timeout);
	return MBEDTLS_ERR_SSL_TIMEOUT;
}

#if defined (MBEDTLS_DEBUG_C)
void SSLDebugCB(void *ctx, int level, const char *file, int line, const char *str)
{
    if(level < DEBUG_LEVEL)
    {
       printf("%s\r\n",str);
    }
}
#endif

int SSLRandomCB( void *p_rng, unsigned char *output, size_t output_len )
{
    int i;

	if(output_len <= 0)
	{
         return (1);
	}
    for(i = 0;i < output_len;i++)
    {
       *output++ = rand() % 0xff;
	}
    srand(rand());
	return (0);
}

int wiz_mbedtls_ssl_connect(int sockfd, uint8_t* saddr, uint16_t sPort, uint32_t timeout)
{
	uint32_t startTick = getTick();
	if(getSn_SR(sockfd) == SOCK_INIT)
	{
		connect(sockfd,saddr,sPort);
		while((getTick() - startTick) <= timeout)
		{
			if(getSn_SR(sockfd) == SOCK_ESTABLISHED)
			{
				return SOCK_ESTABLISHED;
			}
		}
		return WIZ_ERR_CONNECT_TIMEOUT;
	}
	else{
		return getSn_SR(sockfd);
	}
}

unsigned char wiz_mbedtls_ssl_init(wiz_ssl_context* sslContext, uint8_t* SocketHandler)
{
	if(getTick == NULL){
		printf("ERROR: Ticker callback function is not registered.\r\nPlease register ticker function using WIZnetRegFuncTicker()\r\n");
		return 0;
	}
	int ret = 1;
#if defined (MBEDTLS_ERROR_C)
	char error_buf[100];
#endif

#if defined (MBEDTLS_DEBUG_C)
	debug_set_threshold(DEBUG_LEVEL);
#endif

	/*
	Initialize session data
	*/
#if defined (MBEDTLS_ENTROPY_C)
	sslContext->entropy = malloc(sizeof(mbedtls_entropy_context));
	mbedtls_entropy_init( sslContext->entropy);
#endif
	sslContext->ctr_drbg = malloc(sizeof(mbedtls_ctr_drbg_context));
	sslContext->ssl = malloc(sizeof(mbedtls_ssl_context));
	sslContext->conf = malloc(sizeof(mbedtls_ssl_config));
	sslContext->cacert = malloc(sizeof(mbedtls_x509_crt));

	mbedtls_ctr_drbg_init(sslContext->ctr_drbg);
	mbedtls_x509_crt_init(sslContext->cacert);
	mbedtls_ssl_init(sslContext->ssl);
	mbedtls_ssl_config_init(sslContext->conf);
	/*
	Initialize certificates
	*/
#if defined (MBEDTLS_X509_CRT_PARSE_C)
#if defined (MBEDTLS_DEBUG_C)
	printf(" Loading the CA root certificate \r\n");
#endif
	mbedtls_ssl_config_defaults((sslContext->conf),
								MBEDTLS_SSL_IS_CLIENT,
								MBEDTLS_SSL_TRANSPORT_STREAM,
								MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_setup((sslContext->ssl), (sslContext->conf));
	mbedtls_ssl_set_timer_cb(sslContext->ssl,NULL,SSLFSetTimerCB,SSLFGetTimerCB);
	//mbedtls_ssl_set_hostname(sslContext->ssl, HOST_NAME);
#if defined (MBEDTLS_CERTS_C)
	ret = mbedtls_x509_crt_parse((sslContext->cacert),(unsigned char *)CERTIFICATE,strlen(CERTIFICATE));
#else
	ret = 1;
#if defined (MBEDTLS_DEBUG_C)
	printf("SSL_CERTS_C not define .\r\n");
#endif
#endif
#endif
	if(ret < 0)
	{
#if defined (MBEDTLS_CERTS_C)
		printf("x509_crt_parse failed.%x \r\n",ret);
#endif
		return 0;
	}
	/*
	set ssl session para
	*/
	mbedtls_ssl_conf_ca_chain(sslContext->conf, sslContext->cacert, NULL);
	mbedtls_ssl_conf_endpoint(sslContext->conf,MBEDTLS_SSL_IS_CLIENT); 		//set the current communication method is SSL Client
	mbedtls_ssl_conf_authmode(sslContext->conf,MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_rng(sslContext->conf,SSLRandomCB,sslContext->ctr_drbg);
        mbedtls_ssl_conf_read_timeout(sslContext->conf,WIZ_RECV_TIMEOUT_VALUE);
#if defined (MBEDTLS_DEBUG_C)
	mbedtls_ssl_conf_dbg(sslContext->conf,SSLDebugCB,stdout);
#endif
	mbedtls_ssl_set_bio(sslContext->ssl,SocketHandler, SSLSendCB, SSLRecvCB, SSLRecvTimeOutCB);		 //set client's socket send and receive functions

	return 1;
}

void wiz_mbedtls_ssl_deinit(wiz_ssl_context* sslContext)
{
	mbedtls_ssl_free( sslContext->ssl );
	free(sslContext->ssl);
	mbedtls_ssl_config_free( sslContext->conf );
	free(sslContext->conf);
	mbedtls_ctr_drbg_free( sslContext->ctr_drbg );
	free(sslContext->ctr_drbg);
	
#if defined (MBEDTLS_ENTROPY_C)
	mbedtls_entropy_free( sslContext->entropy );
	free(sslContext->entropy);
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
	mbedtls_x509_crt_free( sslContext->cacert );
	free(sslContext->cacert);
#endif
}

unsigned int wiz_mbedtls_ssl_handshake(wiz_ssl_context* sslContext)
{
    int ret;
    uint32_t flags;
//#if defined(MBEDTLS_ERROR_C)
//    unsigned char error_buf[100];
//    memset(error_buf, 0, 100);
//#endif
    printf( "  . Performing the SSL/TLS handshake...\n\r" );

    while( ( ret = mbedtls_ssl_handshake( sslContext->ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
//#if defined(MBEDTLS_ERROR_C)
//            mbedtls_strerror( ret, (char *) error_buf, 100 );
//            printf( " failed\n\r  ! mbedtls_ssl_handshake returned %d: %s\n\r", ret, error_buf );
//#endif
            return( -1 );
        }
    }
    printf( " ok\n\r    [ Ciphersuite is %s ]\n\r",
            mbedtls_ssl_get_ciphersuite( sslContext->ssl ) );

    printf( "  . Verifying peer X.509 certificate..." );

    /* In real life, we probably want to bail out when ret != 0 */
    if( ( flags = mbedtls_ssl_get_verify_result( sslContext->ssl ) ) != 0 )
    {
        //char vrfy_buf[512];

        printf( " failed.\n\r" );

        //mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        //printf( "%s\n\r", vrfy_buf );
    }
    else
        printf( " ok.\n\r" );

    return( 0 );
}
