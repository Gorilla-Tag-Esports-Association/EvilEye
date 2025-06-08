#include <stdio.h>
#include "headers/file_hash.h"
#include "headers/webhook_handler.h"

int main(){
	send_webhook(NULL, "This is a test description", 16711680, "Test Title");
	printf("Webhook sent hopefully");
	return 0;
}
