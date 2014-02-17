#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <getopt.h>
#include <jansson.h>
#include <stdbool.h>

#include "VtFileDist.h"
#include "VtResponse.h"


#define DBG(FMT,ARG...) fprintf(stderr, "%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); 

void print_usage(const char *prog_name)
{
	printf("%s < --apikey YOUR_API_KEY >  [ --all-info ] [ --sleep X ] [ --repeat X ]\n", prog_name);
	printf("  --apikey YOUR_API_KEY  Your virus total API key.  This arg 1st \n");
	printf("  --reports              Get reports\n");
	printf("  --before               before timestamp\n");
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



void file_dist_callback(const char *link, unsigned long long timestamp,
	const char *sha256hash, const char *name, json_t *raw_json, void *data)
{
	struct CallbackData *cb_data = (struct CallbackData *) data;
	char *s;

	cb_data->counter++;
	printf("------------- File %d ----------------\n", cb_data->counter);
	printf("URL: %s \n", link);
	printf("timestamp: %lld\n", timestamp);
	printf("name: %s\n", name);
	printf("sha256: %s\n", sha256hash);
	s = json_dumps(raw_json, JSON_INDENT(4));
	printf("%s \n", s);
	free(s);
	printf("\n");
}

int main(int argc, char * const *argv)
{
	int c;
	int ret = 0;
	struct VtFileDist *file_dist;
	int repeat = 3;
	int sleep_sec = 3;
	struct CallbackData cb_data = { .counter = 0 };



	if (argc < 2) {
		print_usage(argv[0]);
		return 0;
	}

	file_dist = VtFileDist_new();

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"apikey",  required_argument,     0,  'a'},
			{"before",  required_argument,    0,  'b' },
			{"after",  required_argument,     0,  'f'},
			{"limit",  required_argument,     0,  'l'},
			{"reports",  required_argument,     0,  'i'},
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
				VtFileDist_setApiKey(file_dist, optarg);
				break;
			case 'l':
				VtFileDist_setLimit(file_dist, atoi(optarg));
				break;
			case 'i':
				VtFileDist_setReports(file_dist, atoi(optarg));
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
		ret = VtFileDist_process(file_dist, file_dist_callback, &cb_data);
		if (ret) {
			printf("returned error %d\n", ret);
			break;
		}
		if (repeat>1)
			sleep(sleep_sec);
	}

	DBG("Cleanup\n");
	VtFileDist_put(&file_dist);
	return 0;
}
