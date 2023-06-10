// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2013-2019 The Truckcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "ui_interface.h"
#include "init.h"
#include "bitcoinrpc.h"

#include <string>

static bool noui_ThreadSafeMessageBox(const std::string& message, const std::string& caption, int style)
{
    printf("%s: %s\n", caption.c_str(), message.c_str());
    fprintf(stderr, "%s: %s\n", caption.c_str(), message.c_str());
    return false;
}

static bool noui_ThreadSafeAskFee(int64_t nFeeRequired, const std::string& strCaption)
{
    return true;
}

void noui_connect()
{
    // Connect bitcoind signal handlers
    uiInterface.ThreadSafeMessageBox.connect(noui_ThreadSafeMessageBox);
    uiInterface.ThreadSafeAskFee.connect(noui_ThreadSafeAskFee);
}
