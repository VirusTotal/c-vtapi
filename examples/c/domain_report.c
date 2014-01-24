#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <getopt.h>
#include <jansson.h>
#include <stdbool.h>

#include "VtDomain.h"
#include "VtResponse.h"


#define DBG(FMT,ARG...) fprintf(stderr, "%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); 

void print_usage(const char *prog_name)
{
	printf("%s < --apikey YOUR_API_KEY >  < --ip  1.2.3.4. --> \n", prog_name);
	printf("  --apikey YOUR_API_KEY   Your virus total API key.  This arg 1st \n");
	printf("  --ip             IP Address\n");
}

int main(int argc, char * const *argv)
{
	int c;
	int ret = 0;
	struct VtDomain *domain_report;
	struct VtResponse *response;
	char *str = NULL;
	char *api_key = NULL;


	if (argc < 2) {
		print_usage(argv[0]);
		return 0;
	}

	domain_report = VtDomain_new();

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
            {"report",  required_argument,    0,  'r' },
			{"apikey",  required_argument,     0,  'a'},
			{"verbose", optional_argument,  0,  'v' },
			{"help", optional_argument,  0,  'h' },
			{0,         0,                 0,  0 }
		};

		c = getopt_long_only(argc, argv, "",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'a':
				api_key = strdup(optarg);
				printf(" apikey: %s \n", optarg);
				VtDomain_setApiKey(domain_report, optarg);
				break;

			case 'r':
				if (!api_key) {
					printf("Must set --apikey first\n");
					exit(1);
				}

				ret = VtDomain_report(domain_report, optarg);
				DBG("Filescan ret=%d\n", ret);
				if (ret) {
					printf("Error: %d \n", ret);
				} else {
					response = VtDomain_getResponse(domain_report);
					if (response)
						str = VtResponse_toJSONstr(response, VT_JSON_FLAG_INDENT);
					if (str)  {
						printf("Response:\n%s\n", str);
						free(str);
					}
					VtResponse_put(&response);
				}
				break;
			case 'h':
				print_usage(argv[0]);
				break;
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

	DBG("Cleanup\n");
	VtDomain_put(&domain_report);
	if (api_key)
		free(api_key);
	return 0;
}