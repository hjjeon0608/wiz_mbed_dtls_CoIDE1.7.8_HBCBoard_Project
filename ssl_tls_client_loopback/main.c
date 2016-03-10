/*Include: Board configuration*/
#include "IoTEVB.h"

/*Include: MCU peripheral Library*/
#include "stm32f10x_rcc.h"
#include "stm32f10x.h"

/*Include: W5500 iolibrary*/
#include "w5500.h"
#include "wizchip_conf.h"

/*Include: MCU Specific W5500 driver*/
#include "W5500HardwareDriver.h"

/*Include: Standard IO Library*/
#include <stdio.h>

#include "wizInterface.h"
/*Socket number defines*/
#define TCP_SOCKET	0
#define UDP_SOCKET	1

/*Port number defines*/
#define TCP_PORT 	60000
#define UDP_PORT 	60001

/*Receive Buffer Size define*/
#define BUFFER_SIZE	2048

/*Global variables*/
unsigned char testIP[4] = {222,98,173,239};

wiz_NetInfo gWIZNETINFO = { .mac = {0x00, 0x08, 0xdc, 0x1D, 0xFD, 0x39},
							.ip = {192, 168, 0, 180},
							.sn = {255, 255, 255, 0},
							.gw = {192, 168, 0, 1},
							.dns = {168, 126, 63, 1},
							.dhcp = NETINFO_STATIC};

unsigned char tempBuffer[BUFFER_SIZE] = {0,};

/*Start of Main Functions*/
int main(void)
{
	led_ctrl led1,led2;
	uint8_t SSLSockNo = 0;
	wiz_ssl_context sslContext;
	int ret;
	/*Usart initialization for Debug.*/
	USART1Initialze();
		printf("USART initialized.\n\r");
	uint32_t i,j;
	/*LED initialization.*/
	led_initialize();
	led1 = led2 = ON;

	led2Ctrl(led2);
	led1Ctrl(led1);

	/*W5500 initialization.*/
	W5500HardwareInitilize();
		printf("W5500 hardware interface initialized.\n\r");

	W5500Initialze();
		printf("W5500 IC initialized.\n\r");

	/*Set network informations*/
	wizchip_setnetinfo(&gWIZNETINFO);

	print_network_information();
	sysTickInit();
	WIZnetRegFuncTicker(getSysTick);
	wiz_mbedtls_ssl_init(&sslContext,&SSLSockNo);
	wiz_mbedtls_ssl_socket(SSLSockNo,Sn_MR_TCP,3000,0x00);
	wiz_mbedtls_ssl_connect(SSLSockNo,testIP,443,1000);
	ret = wiz_mbedtls_ssl_handshake(&sslContext);
	if(ret == 0)
	{
		while(1)
		{
			memset(tempBuffer,0,BUFFER_SIZE);
			ret = wiz_mbedtls_ssl_read(sslContext.ssl,tempBuffer,BUFFER_SIZE);
			if(ret > 0)
			{
				printf("Received data: %s\r\n",tempBuffer);
				wiz_mbedtls_ssl_write(sslContext.ssl,tempBuffer,ret);
			}

		}
	}
	printf("ERROR: %d\r\n",ret);
}
