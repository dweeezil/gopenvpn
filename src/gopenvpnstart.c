/* gopenvpnstart.c
 * Copyright (C) 2006 Gary Grossman <gary@softwareasart.com>
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

#include "gopenvpn.h"

void check_valid_chars(const char *param_name,
					   const char *test_string,
					   int (*validate_func)(char))
{
	const char *ptr = test_string;

	while (*ptr)
	{
		if (!validate_func(*ptr))
		{
			fprintf(stderr, "invalid characters in %s\n", param_name);
			exit(-1);
		}
		
		ptr++;
	}
}

int is_config_file_char_valid(char ch)
{
	return isalnum(ch) || ch == '.';
}

void check_config_file(const char *config_file)
{
	check_valid_chars("config_file",
					  config_file,
					  is_config_file_char_valid);
}

int is_management_port_char_valid(char ch)
{
	return isdigit(ch);
}

void check_management_port(const char *port_string)
{
	int port;
	
	check_valid_chars("management_port",
					  port_string,
					  is_management_port_char_valid);

	port = atoi(port_string);
	
	if (port < 1024)
	{
		fprintf(stderr, "management_port must not be reserved port (< 1024)\n");
		exit(-1);
	}

	if (port > 65535)
	{
		fprintf(stderr, "management_port must be valid TCP port\n");
		exit(-1);
	}
}
	
int main(int argc, char *argv[])
{
	char *config_file;
	char *management_port;
	
	if (argc != 3)
	{
		fprintf(stderr, "usage: gopenvpnstart config_file management_port\n");
		return -1;
	}

	config_file = argv[1];
	management_port = argv[2];

	/* Validate arguments */
	check_config_file(config_file);
	check_management_port(management_port);

	/* Execute OpenVPN */
	execl(OPENVPN_BINARY_PATH,
		  OPENVPN_BINARY_PATH,
		  "--management-query-passwords",
		  "--cd",
		  CONFIG_PATH,
		  "--daemon",
		  "--management-hold",
		  "--management",
		  "127.0.0.1",
		  management_port,
		  "--config",
		  config_file,
		  NULL);

	return 0;
}
