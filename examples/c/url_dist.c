#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <getopt.h>
#include <jansson.h>
#include <stdbool.h>

#include "VtUrlDist.h"
#include "VtResponse.h"


#define DBG(FMT,ARG...) fprintf(stderr, "%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); 

void print_usage(const char *prog_name)
{
	printf("%s < --apikey YOUR_API_KEY >  [ --all-info ] [ --sleep X ] [ --repeat X ]\n", prog_name);
	printf("  --apikey YOUR_API_KEY   Your virus total API key.  This arg 1st \n");
	printf("  --all-info              When doing a report, set allinfo flag\n");
	printf("  --before                before timestamp\n");
	printf("  --after                before timestamp\n");
	printf("  --limit                limit results\n");
	printf("  --repeat               Repeat X times updating the feeed\n");
	printf("  --sleep                Sleep X seconds between requests\n");
}

// Example data structure that can be passed to callback function
struct CallbackData
{
	int counter;
};




void url_process_callback(const char *url, unsigned long long timestamp, 
int total, int positives, json_t *raw_json, void *data)
{
	struct CallbackData *cb_data = (struct CallbackData *) data;

	cb_data->counter++;
	printf("------------- URL %d ----------------\n", cb_data->counter);
	printf("URL: %s \n", url);
	printf("timestamp: %lld\n", timestamp);
	printf("positives/total = %d / %d \n", positives, total);
	printf("\n");
}

int main(int argc, char * const *argv)
{
	int c;
	int ret = 0;
	struct VtUrlDist *url_dist;
	int repeat = 3;
	int sleep_sec = 3;
	struct CallbackData cb_data = { .counter = 0 };



	if (argc < 2) {
		print_usage(argv[0]);
		return 0;
	}

	url_dist = VtUrlDist_new();

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"apikey",  required_argument,     0,  'a'},
			{"before",  required_argument,    0,  'b' },
			{"after",  required_argument,     0,  'f'},
			{"limit",  required_argument,     0,  'l'},
			{"allinfo",  required_argument,     0,  'i'},
			{"repeat",  required_argument,     0,  'r'},
			{"sleep",  required_argument,     0,  's'},
			{"verbose", optional_argument,  0,  'v' },
			{"help", optional_argument,  0,  'h' },
			{0,         0,                 0,  0 }
		};

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'a':
				VtUrlDist_setApiKey(url_dist, optarg);
				break;
			case 'l':
				VtUrlDist_setLimit(url_dist, atoi(optarg));
				break;
			case 'i':
				VtUrlDist_setAllInfo(url_dist, atoi(optarg));
				break;
			case 'r':
				repeat = atoi(optarg);
				break;
			case 's':
				sleep_sec = atoi(optarg);
				break;
			case 'h':
				print_usage(argv[0]);
				return 0;
			case 'v':
				printf(" verbose selected\n");
				if (optarg)
					printf(" verbose level %s \n", optarg);
				break;
			default:
				printf("?? getopt returned character code 0%o ??\n", c);
			}
	} // end while

	if (optind < argc) {
		printf("non-option ARGV-elements: ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
	}
	
	for (  ;  repeat; repeat--) {
		printf("\n%d requests remaining\n", repeat);
		ret = VtUrlDist_process(url_dist, url_process_callback, &cb_data);
		if (ret) {
			printf("returned error %d\n", ret);
			break;
		}
		if (repeat>1)
			sleep(sleep_sec);
	}

	DBG("Cleanup\n");
	VtUrlDist_put(&url_dist);
	return 0;
}