/*
**      $Id$
*/
/*
 *	File:		io.c
 *
 *	Author:		Jeff W. Boote
 *
 *	Date:		Tue Sep 16 14:26:30 MDT 2003
 *
 *	Description:	This file contains the private functions to
 *			to facilitate IO that the library needs to do.
 *
 *    License:
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the following copyright notice,
 *       this list of conditions and the disclaimer below.
 * 
 *        Copyright (c) 2003-2008, Internet2
 * 
 *                              All rights reserved.
 * 
 *     * Redistribution in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 * 
 *    *  Neither the name of Internet2 nor the names of its contributors may be
 *       used to endorse or promote products derived from this software without
 *       explicit prior written permission.
 * 
 * You are under no obligation whatsoever to provide any enhancements to Internet2,
 * or its contributors.  If you choose to provide your enhancements, or if you
 * choose to otherwise publish or distribute your enhancement, in source code form
 * without contemporaneously requiring end users to enter into a separate written
 * license agreement for such enhancements, then you thereby grant Internet2, its
 * contributors, and its members a non-exclusive, royalty-free, perpetual license
 * to copy, display, install, use, modify, prepare derivative works, incorporate
 * into the software or other computer software, distribute, and sublicense your
 * enhancements or derivative works thereof, in binary and source code form.
 * 
 * DISCLAIMER - THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * “AS IS” AND WITH ALL FAULTS.  THE UNIVERSITY OF DELAWARE, INTERNET2, ITS CONTRI-
 * BUTORS, AND ITS MEMBERS DO NOT IN ANY WAY WARRANT, GUARANTEE, OR ASSUME ANY RES-
 * PONSIBILITY, LIABILITY OR OTHER UNDERTAKING WITH RESPECT TO THE SOFTWARE. ANY E-
 * XPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRAN-
 * TIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT
 * ARE HEREBY DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE,
 * ACCURACY, AND EFFORT IS WITH THE USER THEREOF.  IN NO EVENT SHALL THE COPYRIGHT
 * OWNER, CONTRIBUTORS, OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELO-
 * PMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTIT-
 * UTE GOODS OR SERVICES; REMOVAL OR REINSTALLATION LOSS OF USE, DATA, SAVINGS OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILIT-
 * Y, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHE-
 * RWISE) ARISING IN ANY WAY OUT OF THE USE OR DISTRUBUTION OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
*/
#include <fcntl.h>
#include <bwlibP.h>

int
_BWLSendBlocksIntr(
	BWLControl  cntrl,
	uint8_t	    *buf,
	int	    num_blocks,
	int	    *retn_on_intr
	)
{
	ssize_t	n;

	if (cntrl->mode & BWL_MODE_DOCIPHER)
		_BWLEncryptBlocks(cntrl, buf, num_blocks, buf);

	n = I2Writeni(cntrl->sockfd,buf,
                (unsigned)num_blocks*_BWL_RIJNDAEL_BLOCK_SIZE,retn_on_intr);
	if(n < 0){
		if(!*retn_on_intr || (errno != EINTR)){
			BWLError(cntrl->ctx,BWLErrFATAL,errno,
							"I2Writeni(): %M");
		}
		return -1;
	} 

	return num_blocks;
}

int
_BWLReceiveBlocksIntr(
	BWLControl  cntrl,
	uint8_t	    *buf,
	int	    num_blocks,
	int	    *retn_on_intr
	)
{
	ssize_t	n;

	n = I2Readni(cntrl->sockfd,buf,
                (unsigned)num_blocks*_BWL_RIJNDAEL_BLOCK_SIZE,retn_on_intr);
	if(n < 0){
		if(!*retn_on_intr || (errno != EINTR)){
			BWLError(cntrl->ctx,BWLErrFATAL,errno,"I2Readni(): %M");
		}
		return -1;
	} 

	/*
	 * Short reads mean socket was closed.
	 */
	if(n != (num_blocks*_BWL_RIJNDAEL_BLOCK_SIZE))
		return 0;

	if (cntrl->mode & BWL_MODE_DOCIPHER)
		_BWLDecryptBlocks(cntrl, buf, num_blocks, buf);

	return num_blocks;
}

int
_BWLSendBlocks(
	BWLControl  cntrl,
	uint8_t	    *buf,
	int	    num_blocks
	)
{
	int	intr=0;
	int	*retn_on_intr = &intr;

	if(cntrl->retn_on_intr){
		retn_on_intr = cntrl->retn_on_intr;
	}

	return _BWLSendBlocksIntr(cntrl,buf,num_blocks,retn_on_intr);
}

int
_BWLReceiveBlocks(
	BWLControl  cntrl,
	uint8_t	    *buf,
	int	    num_blocks
	)
{
	int intr=0;
	int *retn_on_intr = &intr;

	if(cntrl->retn_on_intr){
		retn_on_intr = cntrl->retn_on_intr;
	}

	return _BWLReceiveBlocksIntr(cntrl,buf,num_blocks,retn_on_intr);
}

/*
** The following two functions encrypt/decrypt a given number
** of (16-byte) blocks. IV is currently updated within
** the rijndael api (blockEncrypt/blockDecrypt).
*/
int
_BWLEncryptBlocks(
	BWLControl  cntrl,
	uint8_t	    *buf,
	int	    num_blocks,
	uint8_t	    *out
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
_BWLDecryptBlocks(
	BWLControl  cntrl,
	uint8_t	    *buf,
	int	    num_blocks,
	uint8_t	    *out
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
** This function sets up the key field of a BWLControl structure,
** using the binary key located in <binKey>.
*/

void
_BWLMakeKey(
	BWLControl  cntrl,
	uint8_t	    *binKey
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
_BWLEncryptToken(
	unsigned char   *binKey,
	unsigned char	*token_in,
	unsigned char	*token_out
	)
{
	int		r;
	uint8_t	IV[16];
	keyInstance	key;

	memset(IV, 0, 16);
	
	key.Nr = rijndaelKeySetupEnc(key.rk, binKey, 128);
	r = blockEncrypt(IV, &key, token_in, TOKEN_BITS_LEN, token_out); 
			 
	if (r != TOKEN_BITS_LEN)
		return -1;

	return 0;
}

int
_BWLDecryptToken(
	unsigned char	*binKey,
	unsigned char	*token_in,
	unsigned char	*token_out
	)
{
	int		r;
	uint8_t	IV[16];
	keyInstance	key;

	memset(IV, 0, 16);
	
	key.Nr = rijndaelKeySetupDec(key.rk, binKey, 128);
	r = blockDecrypt(IV, &key, token_in, TOKEN_BITS_LEN, token_out); 
			 
	if (r != TOKEN_BITS_LEN)
		return -1;

	return 0;
}
