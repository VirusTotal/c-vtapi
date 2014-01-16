#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <getopt.h>
#include <jansson.h>

#include "VtFileScan.h"
#include "VtResponse.h"


#define DBG(FMT,ARG...) fprintf(stderr, "%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); 

void print_usage(const char *prog_name)
{
	printf("%s < --apikey YOUR_API_KEY >   [ --filescan FILE1 ] [ --filescan FILE2 ]\n", prog_name);
	printf("    --apikey YOUR_API_KEY          Your virus total API key.  This arg 1st \n");
	printf("    --filescan FILE          File to scan.   Note may specify this multiple times for multiple files\n");

}

int main(int argc, char * const *argv)
{
	int c;
	int ret = 0;
	struct VtFileScan *file_scan;
    struct VtResponse *response;
    char *str = NULL;
	char *api_key = NULL;

	if (argc < 2) {
		print_usage(argv[0]);
		return 0;
	}

	file_scan = VtFileScan_new();

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"filescan",  required_argument,    0,  'f' },
            {"rescan",  required_argument,    0,  'r' },
            {"report",  required_argument,    0,  'i' },
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
				VtFileScan_setApiKey(file_scan, optarg);
				break;

			case 'f':
				if (!api_key) {
					printf("Must set --apikey first\n");
					exit(1);
				}

				ret = VtFileScan_scan(file_scan, optarg);
                DBG("Filescan ret=%d\n", ret);
				if (ret) {
					printf("Error: %d \n", ret);
				} else {
                    response = VtFileScan_getResponse(file_scan);
                    str = VtResponse_toJSONstr(response, VT_JSON_FLAG_INDENT);
                    if (str) {
                        printf("Response:\n%s\n", str);
                        free(str);
                    }
                    VtResponse_put(&response);
                }
				break;
            case 'r':
				if (!api_key) {
					printf("Must set --apikey first\n");
					exit(1);
				}
                
				ret = VtFileScan_rescanHash(file_scan, optarg);
                DBG("rescan ret=%d\n", ret);
				if (ret) {
					printf("Error: %d \n", ret);
				} else {
                    response = VtFileScan_getResponse(file_scan);
                    str = VtResponse_toJSONstr(response, VT_JSON_FLAG_INDENT);
                    if (str) {
                        printf("Response:\n%s\n", str);
                        free(str);
                    }
                    VtResponse_put(&response);
                }
				break;
            case 'i':
				if (!api_key) {
					printf("Must set --apikey first\n");
					exit(1);
				}
                
				ret = VtFileScan_report(file_scan, optarg);
                DBG("rescan ret=%d\n", ret);
				if (ret) {
					printf("Error: %d \n", ret);
				} else {
                    response = VtFileScan_getResponse(file_scan);
                    str = VtResponse_toJSONstr(response, VT_JSON_FLAG_INDENT);
                    if (str) {
                        printf("Response:\n%s\n", str);
                        free(str);
                    }
                    VtResponse_put(&response);
                }
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

	DBG("Cleanup\n");
	VtFileScan_put(&file_scan);
	if (api_key)
		free(api_key);
	return 0;
}