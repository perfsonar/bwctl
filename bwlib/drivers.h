/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabs-mode: nil -*-
 *      $Id$
 */
/************************************************************************
*                                                                       *
*                           Copyright (C)  2007                         *
*                               Internet2                               *
*                           All Rights Reserved                         *
*                                                                       *
************************************************************************/
/*
 *    File:         drivers.h
 *
 *    Author:       Jeff W. Boote
 *                  Internet2
 *
 *    Date:         Fri Aug 31 14:03:15 MDT 2007
 *
 *    Description:    
 */
#ifndef BWDRIVERS_H
#define BWDRIVERS_H
#include <bwlib/bwlib.h>

#define BWL_MAX_TOOLNAME    PATH_MAX

typedef struct BWLToolDefinitionRec{
    char        name[BWL_MAX_TOOLNAME];
} BWLToolDefinitionRec, *BWLToolDefinition;

typedef struct BWLToolRec{
    BWLToolType         id; /* what bits define this tool in the protocol? */
    BWLToolDefinition   tool;
} BWLToolRec, *BWLTool;


#endif  /* BWDRIVERS_H */
