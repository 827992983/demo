#include "cfg_op.h"

char CFG_ssl = '[', CFG_ssr = ']';
char CFG_nis = ':';
char CFG_nts = '#';

int CFG_section_line_no, CFG_key_line_no, CFG_key_lines;

static char * strtrimr(char * buf)
{
	int len, i;
	char * tmp = NULL;
	len = strlen(buf);
	tmp = (char*) malloc(len);

	memset(tmp, 0x00, len);
	for (i = 0; i < len; i++)
	{
		if (buf[i] != ' ')
			break;
	}
	if (i < len)
	{
		strncpy(tmp, (buf + i), (len - i));
	}
	strncpy(buf, tmp, len);
	free(tmp);
	return buf;
}

static char * strtriml(char * buf)
{
	int len, i;
	char * tmp = NULL;
	len = strlen(buf);
	tmp = (char*) malloc(len);
	memset(tmp, 0x00, len);
	for (i = 0; i < len; i++)
	{
		if (buf[len - i - 1] != ' ')
			break;
	}
	if (i < len)
	{
		strncpy(tmp, buf, len - i);
	}
	strncpy(buf, tmp, len);
	free(tmp);
	return buf;
}

static int FileGetLine(FILE *fp, char *buffer, int maxlen)
{
	int i, j;
	char ch1;

	for (i = 0, j = 0; i < maxlen; j++)
	{
		if (fread(&ch1, sizeof(char), 1, fp) != 1)
		{
			if (feof(fp) != 0)
			{
				if (j == 0)
					return -1;
				else
					break;
			}
			if (ferror(fp) != 0)
				return -2;
			return -2;
		}
		else
		{
			if (ch1 == '\n' || ch1 == 0x00)
				break;
			if (ch1 == '\f' || ch1 == 0x1A)
			{
				buffer[i++] = ch1;
				break;
			}
			if (ch1 != '\r')
				buffer[i++] = ch1;
		}
	}
	buffer[i] = '\0';
	return i;
}

int FileCopy(void *source_file, void *dest_file)
{
	FILE *fp1, *fp2;
	char buf[1024 + 1];
	int ret;

	if ((fp1 = fopen((char *) source_file, "r")) == NULL)
		return COPYF_ERR_OPEN_FILE;
	ret = COPYF_ERR_CREATE_FILE;

	if ((fp2 = fopen((char *) dest_file, "w")) == NULL)
		goto copy_end;

	while (1)
	{
		ret = COPYF_ERR_READ_FILE;
		memset(buf, 0x00, 1024 + 1);
		if (fgets((char *) buf, 1024, fp1) == NULL)
		{
			if (strlen(buf) == 0)
			{
				if (ferror(fp1) != 0)
					goto copy_end;
				break;
			}
		}
		ret = COPYF_ERR_WRITE_FILE;
		if (fputs((char *) buf, fp2) == EOF)
			goto copy_end;
	}
	ret = COPYF_OK;
	copy_end: if (fp2 != NULL)
		fclose(fp2);
	if (fp1 != NULL)
		fclose(fp1);
	return ret;
}

int SplitSectionToNameIndex(char *section, char **name, char **index)
{
	int i, k1, k2, n;

	if ((n = strlen((char *) section)) < 1)
		return 0;
	for (i = 0; i < n; i++)
		if (section[i] != ' ' && section[i] != '\t')
			break;
	if (i >= n)
		return 0;
	if (section[i] == CFG_nis)
		return -1;
	k1 = i;
	for (i++; i < n; i++)
		if (section[i] == CFG_nis)
			break;
	if (i >= n)
		return -2;
	k2 = i;
	for (i++; i < n; i++)
		if (section[i] != ' ' && section[i] != '\t')
			break;
	section[k2] = '\0';
	*name = section + k1;
	*index = section + i;
	return 1;
}

int JoinNameIndexToSection(char **section, char *name, char *index)
{
	int n1, n2;

	if ((n1 = strlen((char *) name)) < 1)
		return 0;
	if ((n2 = strlen((char *) index)) < 1)
		return 0;

	strcat(*section, name);
	strcat(*section + n1, ":");
	strcat(*section + n1 + 1, index);
	*(*section + n1 + 1 + n2) = '\0';
	return 1;
}

static int SplitKeyValue(char *buf, char **key, char **val)
{
	int i, k1, k2, n;

	if ((n = strlen((char *) buf)) < 1)
		return 0;
	for (i = 0; i < n; i++)
		if (buf[i] != ' ' && buf[i] != '\t')
			break;
	if (i >= n)
		return 0;
	if (buf[i] == '=')
		return -1;
	k1 = i;
	for (i++; i < n; i++)
		if (buf[i] == '=')
			break;
	if (i >= n)
		return -2;
	k2 = i;
	for (i++; i < n; i++)
		if (buf[i] != ' ' && buf[i] != '\t')
			break;
	buf[k2] = '\0';
	*key = buf + k1;
	*val = buf + i;
	return 1;
}

int ConfigGetKey(void *CFG_file, void *section, void *key, void *buf)
{
	FILE *fp;
	char buf1[MAX_CFG_BUF + 1], buf2[MAX_CFG_BUF + 1];
	char *key_ptr, *val_ptr;
	int line_no, n, ret;

	line_no = 0;
	CFG_section_line_no = 0;
	CFG_key_line_no = 0;
	CFG_key_lines = 0;

	if ((fp = fopen((char *) CFG_file, "rb")) == NULL)
		return CFG_ERR_OPEN_FILE;

	while (1)
	{
		ret = CFG_ERR_READ_FILE;
		n = FileGetLine(fp, buf1, MAX_CFG_BUF);
		if (n < -1)
			goto r_cfg_end;
		ret = CFG_SECTION_NOT_FOUND;
		if (n < 0)
			goto r_cfg_end;
		line_no++;
		n = strlen(strtriml(strtrimr(buf1)));
		if (n == 0 || buf1[0] == CFG_nts)
			continue;
		ret = CFG_ERR_FILE_FORMAT;
		if (n > 2 && ((buf1[0] == CFG_ssl && buf1[n - 1] != CFG_ssr)))
			goto r_cfg_end;
		if (buf1[0] == CFG_ssl)
		{
			buf1[n - 1] = 0x00;
			if (strcmp((const char *) (buf1 + 1), (const char *) section) == 0)
				break;
		}
	}
	CFG_section_line_no = line_no;
	while (1)
	{
		ret = CFG_ERR_READ_FILE;
		n = FileGetLine(fp, buf1, MAX_CFG_BUF);
		if (n < -1)
			goto r_cfg_end;
		ret = CFG_KEY_NOT_FOUND;
		if (n < 0)
			goto r_cfg_end;
		line_no++;
		CFG_key_line_no = line_no;
		CFG_key_lines = 1;
		n = strlen(strtriml(strtrimr(buf1)));
		if (n == 0 || buf1[0] == CFG_nts)
			continue;
		ret = CFG_KEY_NOT_FOUND;
		if (buf1[0] == CFG_ssl)
			goto r_cfg_end;
		if (buf1[n - 1] == '+')
		{
			buf1[n - 1] = 0x00;
			while (1)
			{
				ret = CFG_ERR_READ_FILE;
				n = FileGetLine(fp, buf2, MAX_CFG_BUF);
				if (n < -1)
					goto r_cfg_end;
				if (n < 0)
					break;
				line_no++;
				CFG_key_lines++;
				n = strlen(strtrimr(buf2));
				ret = CFG_ERR_EXCEED_BUF_SIZE;
				if (n > 0 && buf2[n - 1] == '+')
				{
					buf2[n - 1] = 0x00;
					if (strlen(buf1) + strlen(buf2) > MAX_CFG_BUF)
						goto r_cfg_end;
					strcat(buf1, buf2);
					continue;
				}
				if (strlen(buf1) + strlen(buf2) > MAX_CFG_BUF)
					goto r_cfg_end;
				strcat(buf1, buf2);
				break;
			}
		}
		ret = CFG_ERR_FILE_FORMAT;
		if (SplitKeyValue(buf1, &key_ptr, &val_ptr) != 1)
			goto r_cfg_end;
		strtriml(strtrimr(key_ptr));
		if (strcmp((const char *) key_ptr, (const char *) key) != 0)
			continue;
		strcpy((char *) buf, (const char *) val_ptr);
		break;
	}
	ret = CFG_OK;
	r_cfg_end: if (fp != NULL)
		fclose(fp);
	return ret;
}

int ConfigSetKey(void *CFG_file, void *section, void *key, void *buf)
{
	FILE *fp1, *fp2;
	char buf1[MAX_CFG_BUF + 1];
	int line_no, line_no1, n, ret, ret2;
	char *tmpfname;

	ret = ConfigGetKey(CFG_file, section, key, buf1);
	if (ret <= CFG_ERR && ret != CFG_ERR_OPEN_FILE)
		return ret;
	if (ret == CFG_ERR_OPEN_FILE || ret == CFG_SECTION_NOT_FOUND)
	{

		if ((fp1 = fopen((char *) CFG_file, "a")) == NULL)

			return CFG_ERR_CREATE_FILE;

		if (fprintf(fp1, "%c%s%c\n", CFG_ssl, (char *)section,CFG_ssr) == EOF)
		{
			fclose(fp1);
			return CFG_ERR_WRITE_FILE;
		}
		if (fprintf(fp1, "%s=%s\n", (char *)key,(char *)buf) == EOF)
		{ 
			fclose(fp1);
			return CFG_ERR_WRITE_FILE;
		}
		fclose(fp1);
		return CFG_OK;
	}
	if ((tmpfname = tmpnam(NULL)) == NULL)
		return CFG_ERR_CREATE_FILE;

	if ((fp2 = fopen(tmpfname, "w")) == NULL)

		return CFG_ERR_CREATE_FILE;
	ret2 = CFG_ERR_OPEN_FILE;

	if ((fp1 = fopen((char *) CFG_file, "rb")) == NULL)
		goto w_cfg_end;

	if (ret == CFG_KEY_NOT_FOUND)
		line_no1 = CFG_section_line_no;
	else
		/* ret = CFG_OK */
		line_no1 = CFG_key_line_no - 1;
	for (line_no = 0; line_no < line_no1; line_no++)
	{
		ret2 = CFG_ERR_READ_FILE;
		n = FileGetLine(fp1, buf1, MAX_CFG_BUF);
		if (n < 0)
			goto w_cfg_end;
		ret2 = CFG_ERR_WRITE_FILE;
		if (fprintf(fp2, "%s\n", buf1) == EOF)
			goto w_cfg_end;
	}
	if (ret != CFG_KEY_NOT_FOUND)
		for (; line_no < line_no1 + CFG_key_lines; line_no++)
		{
			ret2 = CFG_ERR_READ_FILE;
			n = FileGetLine(fp1, buf1, MAX_CFG_BUF);
			if (n < 0)
				goto w_cfg_end;
		}
	ret2 = CFG_ERR_WRITE_FILE;
	if (fprintf(fp2, "%s=%s\n", (char *)key,(char *)buf) == EOF)
		goto w_cfg_end;
	while (1)
	{
		ret2 = CFG_ERR_READ_FILE;
		n = FileGetLine(fp1, buf1, MAX_CFG_BUF);
		if (n < -1)
			goto w_cfg_end;
		if (n < 0)
			break;
		ret2 = CFG_ERR_WRITE_FILE;
		if (fprintf(fp2, "%s\n", buf1) == EOF)
			goto w_cfg_end;
	}
	ret2 = CFG_OK;
	w_cfg_end: if (fp1 != NULL)
		fclose(fp1);
	if (fp2 != NULL)
		fclose(fp2);
	if (ret2 == CFG_OK)
	{
		ret = FileCopy(tmpfname, CFG_file);
		if (ret != 0)
			return CFG_ERR_CREATE_FILE;
	}
	remove(tmpfname);
	return ret2;
}

int ConfigGetSections(void *CFG_file, char *sections[])
{
	FILE *fp;
	char buf1[MAX_CFG_BUF + 1];
	int n, n_sections = 0, ret;

	if ((fp = fopen((const char *) CFG_file, (const char *) "rb")) == NULL)
		return CFG_ERR_OPEN_FILE;

	while (1)
	{
		ret = CFG_ERR_READ_FILE;
		n = FileGetLine(fp, buf1, MAX_CFG_BUF);
		if (n < -1)
			goto cfg_scts_end;
		if (n < 0)
			break;
		n = strlen(strtriml(strtrimr(buf1)));
		if (n == 0 || buf1[0] == CFG_nts)
			continue;
		ret = CFG_ERR_FILE_FORMAT;
		if (n > 2 && ((buf1[0] == CFG_ssl && buf1[n - 1] != CFG_ssr)))
			goto cfg_scts_end;
		if (buf1[0] == CFG_ssl)
		{
			buf1[n - 1] = 0x00;
			strcpy(sections[n_sections], buf1 + 1);
			n_sections++;
		}
	}
	ret = n_sections;
	cfg_scts_end: if (fp != NULL)
		fclose(fp);
	return ret;
}

int ConfigGetKeys(void *CFG_file, void *section, char *keys[])
{
	FILE *fp;
	char buf1[MAX_CFG_BUF + 1], buf2[MAX_CFG_BUF + 1];
	char *key_ptr, *val_ptr;
	int n, n_keys = 0, ret;

	if ((fp = fopen((const char *) CFG_file, (const char *) "rb")) == NULL)
		return CFG_ERR_OPEN_FILE;

	while (1)
	{
		ret = CFG_ERR_READ_FILE;
		n = FileGetLine(fp, buf1, MAX_CFG_BUF);
		if (n < -1)
			goto cfg_keys_end;
		ret = CFG_SECTION_NOT_FOUND;
		if (n < 0)
			goto cfg_keys_end;
		n = strlen(strtriml(strtrimr(buf1)));
		if (n == 0 || buf1[0] == CFG_nts)
			continue;
		ret = CFG_ERR_FILE_FORMAT;
		if (n > 2 && ((buf1[0] == CFG_ssl && buf1[n - 1] != CFG_ssr)))
			goto cfg_keys_end;
		if (buf1[0] == CFG_ssl)
		{
			buf1[n - 1] = 0x00;
			if (strcmp((const char *) (buf1 + 1), (const char *) section) == 0)
				break;
		}
	}
	while (1)
	{
		ret = CFG_ERR_READ_FILE;
		n = FileGetLine(fp, buf1, MAX_CFG_BUF);
		if (n < -1)
			goto cfg_keys_end;
		if (n < 0)
			break;
		n = strlen(strtriml(strtrimr(buf1)));
		if (n == 0 || buf1[0] == CFG_nts)
			continue;
		ret = CFG_KEY_NOT_FOUND;
		if (buf1[0] == CFG_ssl)
			break;
		if (buf1[n - 1] == '+')
		{
			buf1[n - 1] = 0x00;
			while (1)
			{
				ret = CFG_ERR_READ_FILE;
				n = FileGetLine(fp, buf2, MAX_CFG_BUF);
				if (n < -1)
					goto cfg_keys_end;
				if (n < 0)
					break;
				n = strlen(strtrimr(buf2));
				ret = CFG_ERR_EXCEED_BUF_SIZE;
				if (n > 0 && buf2[n - 1] == '+')
				{
					buf2[n - 1] = 0x00;
					if (strlen(buf1) + strlen(buf2) > MAX_CFG_BUF)
						goto cfg_keys_end;
					strcat(buf1, buf2);
					continue;
				}
				if (strlen(buf1) + strlen(buf2) > MAX_CFG_BUF)
					goto cfg_keys_end;
				strcat(buf1, buf2);
				break;
			}
		}
		ret = CFG_ERR_FILE_FORMAT;
		if (SplitKeyValue(buf1, &key_ptr, &val_ptr) != 1)
			goto cfg_keys_end;
		strtriml(strtrimr(key_ptr));
		strcpy(keys[n_keys], key_ptr);
		n_keys++;
	}
	ret = n_keys;
	cfg_keys_end: if (fp != NULL)
		fclose(fp);
	return ret;
}
