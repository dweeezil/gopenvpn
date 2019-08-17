/* gopenvpn.h
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

#define CLOSED_IMAGE       "gopenvpn-closed.png"

#define CONNECTING_IMAGE   "gopenvpn-connecting.png"

#define BLINK_IMAGE        "gopenvpn-blink.png"

#define OPEN_IMAGE         "gopenvpn-open.png"

/* For AppIndicator */
#define CLOSED_IMAGE_AI    "gopenvpn-inactive"

#define CONNECTING_IMAGE_AI "gopenvpn-processing"

#define BLINK_IMAGE_AI     "gopenvpn-processing-2"

#define OPEN_IMAGE_AI      "gopenvpn-active"

#define GLADE_FILE         "gopenvpn.glade"

#define CONFIG_PATH        "/etc/openvpn"

#define MAX_RETRY          10

#ifdef HAVE_LIBSECRET
const SecretSchema * gopenvpn_get_secret_schema (void) G_GNUC_CONST;

#define GOPENVPN_SECRET_SCHEMA  gopenvpn_get_secret_schema ()
#endif
