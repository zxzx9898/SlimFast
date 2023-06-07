#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>

double time_diff(struct timeval x , struct timeval y)
{
	double x_us , y_us , diff;
	
	x_us = (double)x.tv_sec*1000000 + (double)x.tv_usec;
	y_us = (double)y.tv_sec*1000000 + (double)y.tv_usec;
	
	diff = (double)y_us - (double)x_us;

	if(diff<0)
	{
		fprintf(stderr, "ERROR! time_diff<0\n");
		printf("ERROR! time_diff<0\n");
		fflush(stdout);
		exit(1);
	}

	// printf("time_diff: %f\n",diff);
	
	return diff;
}

