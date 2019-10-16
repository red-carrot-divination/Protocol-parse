typedef struct
{
	double first;
	double center;
	char *program_name;
	u_char *colname_flag;
	u_char *coltype_flag;
	int rowsum;
	int reassembled_flag;
	int tds_flag;
	int print_flag;
	
	
	
	
}Global_variable;

typedef struct
{
	int tds_login;
	int tds_login_curror;
	int tds_frag_flag;
	
}Fragment_flag;
