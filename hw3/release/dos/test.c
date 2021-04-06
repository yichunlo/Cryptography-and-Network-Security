#include<stdio.h>

int main(void){
	int *p;
	int a[5];
	int cnt = 0;
	for(int i = 0; i < 5; i++){
		a[i] = cnt;
		cnt += 1;
	}
	p = a;
	for(int i = 0; i < 5; i++)
		printf("p[%d] = %d\n", i, *(p + i));
	return 0;
}
