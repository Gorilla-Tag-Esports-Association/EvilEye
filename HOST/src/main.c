#include <stdio.h>
#include "headers/webhook_handler.h"


int main(){
	send_webhook("hi");
	printf("Webhook sent hopefully");
	return 0;
}
