/*
**      $Id$
*/
/************************************************************************
*									*
*			     Copyright (C)  2003			*
*				Internet2				*
*			     All Rights Reserved			*
*									*
************************************************************************/
/*
**	File:		io.c
**
**	Author:		Jeff W. Boote
**
**	Date:		Tue Sep 16 14:26:30 MDT 2003
**
**	Description:	This file contains the private functions to
**			to facilitate IO that the library needs to do.
*/
#include <fcntl.h>
#include <ipcntrlP.h>

int
_IPFSendBlocksIntr(
	IPFControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks,
	int		*retn_on_intr
	)
{
	ssize_t		n;

	if (cntrl->mode & IPF_MODE_DOCIPHER)
		_IPFEncryptBlocks(cntrl, buf, num_blocks, buf);

	n = I2Writeni(cntrl->sockfd,buf,num_blocks*_IPF_RIJNDAEL_BLOCK_SIZE,
			retn_on_intr);
	if(n < 0){
		if(!*retn_on_intr || (errno != EINTR)){
			IPFError(cntrl->ctx,IPFErrFATAL,errno,
							"I2Writeni(): %M");
		}
		return -1;
	} 

	return num_blocks;
}

int
_IPFReceiveBlocksIntr(
	IPFControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks,
	int		*retn_on_intr
	)
{
	ssize_t		n;

	n = I2Readni(cntrl->sockfd,buf,num_blocks*_IPF_RIJNDAEL_BLOCK_SIZE,
								retn_on_intr);
	if(n < 0){
		if(!*retn_on_intr || (errno != EINTR)){
			IPFError(cntrl->ctx,IPFErrFATAL,errno,"I2Readni(): %M");
		}
		return -1;
	} 

	/*
	 * Short reads mean socket was closed.
	 */
	if(n != (num_blocks*_IPF_RIJNDAEL_BLOCK_SIZE))
		return 0;

	if (cntrl->mode & IPF_MODE_DOCIPHER)
		_IPFDecryptBlocks(cntrl, buf, num_blocks, buf);

	return num_blocks;
}

int
_IPFSendBlocks(
	IPFControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks
	)
{
	int	intr=0;

	return _IPFSendBlocksIntr(cntrl,buf,num_blocks,&intr);
}

int
_IPFReceiveBlocks(
	IPFControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks
	)
{
	int	intr=0;

	return _IPFReceiveBlocksIntr(cntrl,buf,num_blocks,&intr);
}

/*
** The following two functions encrypt/decrypt a given number
** of (16-byte) blocks. IV is currently updated within
** the rijndael api (blockEncrypt/blockDecrypt).
*/
int
_IPFEncryptBlocks(
	IPFControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks,
	u_int8_t	*out
	)
{
	int r;
	r = blockEncrypt(cntrl->writeIV, 
			 &cntrl->encrypt_key, buf, num_blocks*16*8, out);
	if (r != num_blocks*16*8)
		return -1;
	return 0;
}


int
_IPFDecryptBlocks(
	IPFControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks,
	u_int8_t	*out
	)
{
	int r;
	r = blockDecrypt(cntrl->readIV, 
			 &cntrl->decrypt_key, buf, num_blocks*16*8, out);
	if (r != num_blocks*16*8)
		return -1;
	return 0;
}

/*
** This function sets up the key field of a IPFControl structure,
** using the binary key located in <binKey>.
*/

void
_IPFMakeKey(
	IPFControl	cntrl,
	u_int8_t	*binKey
	)
{
	cntrl->encrypt_key.Nr
		= rijndaelKeySetupEnc(cntrl->encrypt_key.rk, binKey, 128);
	cntrl->decrypt_key.Nr 
		= rijndaelKeySetupDec(cntrl->decrypt_key.rk, binKey, 128);
}


/* 
** The next two functions perform a single encryption/decryption
** of Token in Control protocol, using a given (binary) key and the IV of 0.
*/

#define TOKEN_BITS_LEN (2*16*8)

int
IPFEncryptToken(
	unsigned char	*binKey,
	unsigned char	*token_in,
	unsigned char	*token_out
	)
{
	int		r;
	u_int8_t	IV[16];
	keyInstance	key;

	memset(IV, 0, 16);
	
	key.Nr = rijndaelKeySetupEnc(key.rk, binKey, 128);
	r = blockEncrypt(IV, &key, token_in, TOKEN_BITS_LEN, token_out); 
			 
	if (r != TOKEN_BITS_LEN)
		return -1;

	return 0;
}

int
IPFDecryptToken(
	unsigned char	*binKey,
	unsigned char	*token_in,
	unsigned char	*token_out
	)
{
	int		r;
	u_int8_t	IV[16];
	keyInstance	key;

	memset(IV, 0, 16);
	
	key.Nr = rijndaelKeySetupDec(key.rk, binKey, 128);
	r = blockDecrypt(IV, &key, token_in, TOKEN_BITS_LEN, token_out); 
			 
	if (r != TOKEN_BITS_LEN)
		return -1;

	return 0;
}
