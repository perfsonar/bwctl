/*
 *      $Id$
 */
/************************************************************************
*									*
*			     Copyright (C)  2003			*
*				Internet2				*
*			     All Rights Reserved			*
*									*
************************************************************************/
/*
 *	File:		util.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Tue Sep 16 14:27:47 MDT 2003
 *
 *	Description:	
 */
#include <ctype.h>
#include <ipcntrl/ipcntrl.h>

/*
 * buff must be at least (nbytes*2) +1 long or memory will be over-run.
 */
void
IPFHexEncode(
	char		*buff,
	u_int8_t	*bytes,
	unsigned int	nbytes
	)
{
	char		hex[]="0123456789abcdef";
	unsigned int	i;

	for(i=0;i<nbytes;i++){
		*buff++ = hex[*bytes >> 4];
		*buff++ = hex[*bytes++ & 0x0f];
	}
	*buff = '\0';
}

/*
 * Function:	IPFHexDecode
 *
 * Description:	
 * 	Decode hex chars into bytes. Return True on success, False on error.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
IPFBoolean
IPFHexDecode(
	char		*buff,
	u_int8_t	*bytes,
	unsigned int	nbytes
	)
{
	char		hex[]="0123456789abcdef";
	unsigned int	i,j,offset;
	char		a;

	for(i=0;i<nbytes;i++,bytes++){
		*bytes = 0;
		for(j=0;(*buff != '\0')&&(j<2);j++,buff++){
			a = tolower(*buff);
			for(offset=0;offset<sizeof(hex);offset++){
				if(a == hex[offset]){
					*bytes |= offset;
					if(!j)
						*bytes <<= 4;
					goto byteset;
				}
			}
			return False;
byteset:
			;
		}
	}

	return True;
}

