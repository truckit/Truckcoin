/*
 * Qt4 bitcoin GUI.
 *
 * W.J. van der Laan 2011-2012
 * The Bitcoin Developers 2011-2012
 */
#include "bitcoingui.h"
#include "transactiontablemodel.h"
#include "addressbookpage.h"
#include "sendcoinsdialog.h"
#include "signverifymessagedialog.h"
#include "optionsdialog.h"
#include "aboutdialog.h"
#include "clientmodel.h"
#include "walletmodel.h"
#include "editaddressdialog.h"
#include "optionsmodel.h"
#include "transactiondescdialog.h"
#include "addresstablemodel.h"
#include "transactionview.h"
#include "overviewpage.h"
#include "bitcoinunits.h"
#include "guiconstants.h"
#include "askpassphrasedialog.h"
#include "notificator.h"
#include "guiutil.h"
#include "rpcconsole.h"
#include "wallet.h"
#include "bitcoinrpc.h"
#include "ui_interface.h"
#include "blockbrowser.h"
#include "stakereportdialog.h"

#ifdef Q_OS_MAC
#include "macdockiconhandler.h"
#endif

#include <QDebug>
#include <QApplication>
#include <QMainWindow>
#include <QMenuBar>
#include <QMenu>
#include <QIcon>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QToolBar>
#include <QStatusBar>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QLocale>
#include <QMessageBox>
#include <QProgressBar>
#include <QStackedWidget>
#include <QDateTime>
#include <QMovie>
#include <QFileDialog>
#include <QDesktopServices>
#include <QTimer>
#include <QDragEnterEvent>
#if QT_VERSION < 0x050000
#include <QUrl>
#endif
#include <QStyle>
#include <QMimeData>

#include <iostream>

extern CWallet *pwalletMain;
extern int64_t nLastCoinStakeSearchInterval;
extern unsigned int nStakeTargetSpacing;

BitcoinGUI::BitcoinGUI(QWidget *parent):
    QMainWindow(parent),
    clientModel(0),
    walletModel(0),
    encryptWalletAction(0),
    unlockWalletforposAction(0),
    unlockWalletAction(0),
    lockWalletAction(0),
    changePassphraseAction(0),
    aboutQtAction(0),
    trayIcon(0),
    notificator(0),
    rpcConsole(0),
    blockBrowser(0)
{
    updateStyle();
    resize(860, 600);
    setWindowTitle(tr("Truckcoin") + " - " + tr("Wallet ") + QString::fromStdString(FormatFullVersion()));
#ifndef Q_OS_MAC
    qApp->setWindowIcon(QIcon(":icons/bitcoin"));
    setWindowIcon(QIcon(":icons/bitcoin"));
#else
    setUnifiedTitleAndToolBarOnMac(true);
    QApplication::setAttribute(Qt::AA_DontShowIconsInMenus);
#endif
    // Accept D&D of URIs
    setAcceptDrops(true);

    // Create actions for the toolbar, menu bar and tray/dock icon
    createActions();

    // Create application menu bar
    createMenuBar();

    // Create the toolbars
    createToolBars();

    // Create system tray icon and notification
    createTrayIcon();

    // Create tabs
    overviewPage = new OverviewPage();
    blockBrowser = new BlockBrowser(this);
    transactionsPage = new QWidget(this);
    QVBoxLayout *vbox = new QVBoxLayout();
    transactionView = new TransactionView(this);
    vbox->addWidget(transactionView);
    transactionsPage->setLayout(vbox);

    addressBookPage = new AddressBookPage(AddressBookPage::ForEditing, AddressBookPage::SendingTab);

    receiveCoinsPage = new AddressBookPage(AddressBookPage::ForEditing, AddressBookPage::ReceivingTab);

    sendCoinsPage = new SendCoinsDialog(this);

    signVerifyMessageDialog = new SignVerifyMessageDialog(this);

    centralWidget = new QStackedWidget(this);
    centralWidget->addWidget(overviewPage);
    centralWidget->addWidget(transactionsPage);
    centralWidget->addWidget(addressBookPage);
    centralWidget->addWidget(receiveCoinsPage);
    centralWidget->addWidget(sendCoinsPage);
    centralWidget->addWidget(blockBrowser);
    setCentralWidget(centralWidget);

    // Create status bar
    statusBar();

    // Status bar notification icons
    QFrame *frameBlocks = new QFrame();
    frameBlocks->setContentsMargins(0,0,0,0);
    frameBlocks->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
    QHBoxLayout *frameBlocksLayout = new QHBoxLayout(frameBlocks);
    frameBlocksLayout->setContentsMargins(3,0,3,0);
    frameBlocksLayout->setSpacing(3);
    labelEncryptionIcon = new GUIUtil::ClickableLabel();
    labelMintingIcon = new QLabel();
    labelConnectionsIcon = new QLabel();
    labelBlocksIcon = new QLabel();
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelEncryptionIcon);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelMintingIcon);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelConnectionsIcon);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelBlocksIcon);
    frameBlocksLayout->addStretch();

    // Set minting pixmap
    labelMintingIcon->setPixmap(QIcon(":/icons/minting").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
    labelMintingIcon->setEnabled(false);
    // Add timer to update minting info
    QTimer *timerMintingIcon = new QTimer(labelMintingIcon);
    timerMintingIcon->start(MODEL_UPDATE_DELAY);
    connect(timerMintingIcon, SIGNAL(timeout()), this, SLOT(updateMintingIcon()));
    // Add timer to update minting weights
    QTimer *timerMintingWeights = new QTimer(labelMintingIcon);
    timerMintingWeights->start(30 * 1000);
    connect(timerMintingWeights, SIGNAL(timeout()), this, SLOT(updateMintingWeights()));
    // Set initial values for user and network weights
    nWeight, nHoursToMaturity, nNetworkWeight = 0;

    // Progress bar and label for blocks download
    progressBarLabel = new QLabel();
    progressBarLabel->setVisible(false);
    progressBar = new QProgressBar();
    progressBar->setAlignment(Qt::AlignCenter);
    progressBar->setVisible(false);

    // Override style sheet for progress bar for styles that have a segmented progress bar,
    // as they make the text unreadable (workaround for issue #1071)
    // See https://qt-project.org/doc/qt-4.8/gallery.html
    QString curStyle = qApp->style()->metaObject()->className();
    if(curStyle == "QWindowsStyle" || curStyle == "QWindowsXPStyle")
    {
        progressBar->setStyleSheet("QProgressBar { background-color: #e8e8e8; border: 1px solid grey; border-radius: 7px; padding: 1px; text-align: center; } QProgressBar::chunk { background: QLinearGradient(x1: 0, y1: 0, x2: 1, y2: 0, stop: 0 #FF8000, stop: 1 orange); border-radius: 7px; margin: 0px; }");
    }

    statusBar()->addWidget(progressBarLabel);
    statusBar()->addWidget(progressBar);
    statusBar()->addPermanentWidget(frameBlocks);

    syncIconMovie = new QMovie(":/movies/update_spinner", "mng", this);
    // this->setStyleSheet("background-color: #effbef;");

    // Clicking on a transaction on the overview page simply sends you to transaction history page
    connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), this, SLOT(gotoHistoryPage()));
    connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), transactionView, SLOT(focusTransaction(QModelIndex)));

    // Double-clicking on a transaction on the transaction history page shows details
    connect(transactionView, SIGNAL(doubleClicked(QModelIndex)), transactionView, SLOT(showDetails()));

    rpcConsole = new RPCConsole(this);
    connect(openInfoAction, SIGNAL(triggered()), rpcConsole, SLOT(showTab_Info()));
    connect(openTrafficAction, SIGNAL(triggered()), rpcConsole, SLOT(showTab_Traffic()));
    connect(openRPCConsoleAction, SIGNAL(triggered()), rpcConsole, SLOT(showTab_Debug()));

    blockBrowser = new BlockBrowser(this);
    connect(blockAction, SIGNAL(triggered()), blockBrowser, SLOT(show()));

    // Clicking on "Verify Message" in the address book sends you to the verify message tab
    connect(addressBookPage, SIGNAL(verifyMessage(QString)), this, SLOT(gotoVerifyMessageTab(QString)));
    // Clicking on "Sign Message" in the receive coins page sends you to the sign message tab
    connect(receiveCoinsPage, SIGNAL(signMessage(QString)), this, SLOT(gotoSignMessageTab(QString)));

    // Clicking on "Block Explorer" in the transaction page sends you to the blockbrowser
    connect(transactionView, SIGNAL(blockBrowserSignal(QString)), this, SLOT(gotoBlockBrowser(QString)));
  
    gotoOverviewPage();
}

BitcoinGUI::~BitcoinGUI()
{
    if(trayIcon) // Hide tray icon, as deleting will let it linger until quit (on Ubuntu)
        trayIcon->hide();
#ifdef Q_OS_MAC
    delete appMenuBar;
    MacDockIconHandler::cleanup();
#endif
}

void BitcoinGUI::createActions()
{
    QActionGroup *tabGroup = new QActionGroup(this);

    overviewAction = new QAction(QIcon(":/icons/overview"), tr("&Overview"), this);
    overviewAction->setToolTip(tr("Show general overview of wallet"));
    overviewAction->setCheckable(true);
    overviewAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_1));
    tabGroup->addAction(overviewAction);

    sendCoinsAction = new QAction(QIcon(":/icons/send"), tr("&Send coins"), this);
    sendCoinsAction->setToolTip(tr("Send coins to a Truckcoin address"));
    sendCoinsAction->setCheckable(true);
    sendCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_2));
    tabGroup->addAction(sendCoinsAction);

    receiveCoinsAction = new QAction(QIcon(":/icons/receiving_addresses"), tr("&Receive coins"), this);
    receiveCoinsAction->setToolTip(tr("Show the list of addresses for receiving payments"));
    receiveCoinsAction->setCheckable(true);
    receiveCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_3));
    tabGroup->addAction(receiveCoinsAction);

    historyAction = new QAction(QIcon(":/icons/history"), tr("&Transactions"), this);
    historyAction->setToolTip(tr("Browse transaction history"));
    historyAction->setCheckable(true);
    historyAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_4));
    tabGroup->addAction(historyAction);

    addressBookAction = new QAction(QIcon(":/icons/address-book"), tr("&Address Book"), this);
    addressBookAction->setToolTip(tr("Edit the list of stored addresses and labels"));
    addressBookAction->setCheckable(true);
    addressBookAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_5));
    tabGroup->addAction(addressBookAction);

    connect(overviewAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(overviewAction, SIGNAL(triggered()), this, SLOT(gotoOverviewPage()));
    connect(sendCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(sendCoinsAction, SIGNAL(triggered()), this, SLOT(gotoSendCoinsPage()));
    connect(receiveCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(receiveCoinsAction, SIGNAL(triggered()), this, SLOT(gotoReceiveCoinsPage()));
    connect(historyAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(historyAction, SIGNAL(triggered()), this, SLOT(gotoHistoryPage()));
    connect(addressBookAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(addressBookAction, SIGNAL(triggered()), this, SLOT(gotoAddressBookPage()));

    quitAction = new QAction(QIcon(":/icons/quit"), tr("E&xit"), this);
    quitAction->setToolTip(tr("Quit application"));
    quitAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_Q));
    quitAction->setMenuRole(QAction::QuitRole);
    aboutAction = new QAction(QIcon(":/icons/bitcoin"), tr("&About Truckcoin"), this);
    aboutAction->setToolTip(tr("Show information about Truckcoin"));
    aboutAction->setMenuRole(QAction::AboutRole);
    aboutQtAction = new QAction(QIcon(":/trolltech/qmessagebox/images/qtlogo-64.png"), tr("About &Qt"), this);
    aboutQtAction->setToolTip(tr("Show information about Qt"));
    aboutQtAction->setMenuRole(QAction::AboutQtRole);
    stakeMinerToggleAction = new QAction(this);
    stakeMinerToggle(true);
    optionsAction = new QAction(QIcon(":/icons/options"), tr("&Options..."), this);
    optionsAction->setToolTip(tr("Modify configuration options for Truckcoin"));
    optionsAction->setMenuRole(QAction::PreferencesRole);
    toggleHideAction = new QAction(QIcon(":/icons/bitcoin"), tr("&Show / Hide"), this);
    encryptWalletAction = new QAction(QIcon(":/icons/lock_closed"), tr("&Encrypt Wallet..."), this);
    encryptWalletAction->setToolTip(tr("Encrypt the private keys that belong to your wallet"));
    encryptWalletAction->setCheckable(true);
    unlockWalletforposAction = new QAction(QIcon(":/icons/lock_open"), tr("&Unlock Wallet For PoS..."), this); 
    unlockWalletforposAction->setStatusTip(tr("Unlock the wallet for PoS")); 
    unlockWalletforposAction->setCheckable(true); 
    unlockWalletAction = new QAction(QIcon(":/icons/lock_open"), tr("&Unlock Wallet..."), this); 
    unlockWalletAction->setStatusTip(tr("Unlock the wallet")); 
    unlockWalletAction->setCheckable(true); 
    lockWalletAction = new QAction(QIcon(":/icons/lock_closed"), tr("&Lock Wallet..."), this); 
    lockWalletAction->setStatusTip(tr("Lock the wallet")); 
    lockWalletAction->setCheckable(true); 
    checkWalletAction = new QAction(QIcon(":/icons/inspect"), tr("&Check Wallet..."), this); 
    checkWalletAction->setStatusTip(tr("Check wallet integrity and report findings")); 
    repairWalletAction = new QAction(QIcon(":/icons/repair"), tr("&Repair Wallet..."), this); 
    repairWalletAction->setStatusTip(tr("Fix wallet integrity and remove orphans")); 
    backupWalletAction = new QAction(QIcon(":/icons/filesave"), tr("&Backup Wallet..."), this);
    backupWalletAction->setToolTip(tr("Backup wallet to another location"));
    dumpWalletAction = new QAction(QIcon(":/icons/exportw"), tr("&Export Wallet..."), this);
    dumpWalletAction->setStatusTip(tr("Export wallet's keys to a text file"));
    importWalletAction = new QAction(QIcon(":/icons/importw"), tr("&Import Wallet..."), this);
    importWalletAction->setStatusTip(tr("Import a file's keys into a wallet"));
    changePassphraseAction = new QAction(QIcon(":/icons/key"), tr("&Change Passphrase..."), this);
    changePassphraseAction->setToolTip(tr("Change the passphrase used for wallet encryption"));
    signMessageAction = new QAction(QIcon(":/icons/edit"), tr("Sign &message..."), this);
    verifyMessageAction = new QAction(QIcon(":/icons/verify"), tr("&Verify message..."), this);

    stakeReportAction = new QAction(QIcon(":/icons/minting"), tr("Show stake report"), this);
    stakeReportAction->setToolTip(tr("Open the Stake Report Box"));

    exportAction = new QAction(QIcon(":/icons/export"), tr("&Export..."), this);
    exportAction->setToolTip(tr("Export the data in the current tab to a file"));

    openRPCConsoleAction = new QAction(QIcon(":/icons/debugwindow"), tr("&Debug window"), this);
    openRPCConsoleAction->setToolTip(tr("Open debugging and diagnostic console"));
 
    openTrafficAction = new QAction(QIcon(":/icons/graph"), tr("Network Traffic Graph"), this);
    openTrafficAction->setToolTip(tr("Open Network Traffic Graph"));

    openInfoAction = new QAction(QIcon(":/icons/info"), tr("General Info"), this);
    openInfoAction->setToolTip(tr("Open General Info Window"));

    blockAction = new QAction(QIcon(":/icons/blexp"), tr("&Block Explorer"), this);
    blockAction->setToolTip(tr("Explore the BlockChain"));

    connect(quitAction, SIGNAL(triggered()), qApp, SLOT(quit()));
    connect(aboutAction, SIGNAL(triggered()), this, SLOT(aboutClicked()));
    connect(aboutQtAction, SIGNAL(triggered()), qApp, SLOT(aboutQt()));
    connect(stakeMinerToggleAction, SIGNAL(triggered()), this, SLOT(stakeMinerToggle()));
    connect(optionsAction, SIGNAL(triggered()), this, SLOT(optionsClicked()));
    connect(toggleHideAction, SIGNAL(triggered()), this, SLOT(toggleHidden()));
    connect(encryptWalletAction, SIGNAL(triggered(bool)), this, SLOT(encryptWallet(bool)));
    connect(checkWalletAction, SIGNAL(triggered()), this, SLOT(checkWallet())); 
    connect(repairWalletAction, SIGNAL(triggered()), this, SLOT(repairWallet())); 
    connect(backupWalletAction, SIGNAL(triggered()), this, SLOT(backupWallet()));
    connect(changePassphraseAction, SIGNAL(triggered()), this, SLOT(changePassphrase()));
    connect(signMessageAction, SIGNAL(triggered()), this, SLOT(gotoSignMessageTab()));
    connect(verifyMessageAction, SIGNAL(triggered()), this, SLOT(gotoVerifyMessageTab()));
    connect(dumpWalletAction, SIGNAL(triggered()), this, SLOT(dumpWallet()));
    connect(importWalletAction, SIGNAL(triggered()), this, SLOT(importWallet()));
    connect(unlockWalletforposAction, SIGNAL(triggered()), this, SLOT(unlockWalletForMint()));
    connect(unlockWalletAction, SIGNAL(triggered()), this, SLOT(unlockWallet()));
    connect(lockWalletAction, SIGNAL(triggered()), this, SLOT(lockWallet()));
    connect(blockAction, SIGNAL(triggered()), this, SLOT(gotoBlockBrowser()));
    connect(stakeReportAction, SIGNAL(triggered()), this, SLOT(stakeReportClicked()));
}

void BitcoinGUI::createMenuBar()
{
#ifdef Q_OS_MAC
    // Create a decoupled menu bar on Mac which stays even if the window is closed
    appMenuBar = new QMenuBar();
#else
    // Get the main window's menu bar on other platforms
    appMenuBar = menuBar();
#endif

    // Configure the menus
    QMenu *file = appMenuBar->addMenu(tr("&File"));
    file->addAction(backupWalletAction);
    file->addSeparator();
    file->addAction(dumpWalletAction);
    file->addAction(importWalletAction);
    file->addSeparator();
    file->addAction(exportAction);
    file->addSeparator();
    file->addAction(quitAction);

    QMenu *settings = appMenuBar->addMenu(tr("&Settings"));
    settings->addAction(stakeMinerToggleAction);
    settings->addSeparator();
    settings->addAction(optionsAction);

    QMenu *wallet = appMenuBar->addMenu(tr("&Wallet")); 
    wallet->addAction(encryptWalletAction); 
    wallet->addAction(changePassphraseAction); 
    wallet->addAction(unlockWalletforposAction);
    wallet->addAction(unlockWalletAction);
    wallet->addAction(lockWalletAction);
    wallet->addSeparator(); 
    wallet->addAction(checkWalletAction); 
    wallet->addAction(repairWalletAction); 
    wallet->addSeparator();
    wallet->addAction(signMessageAction);
    wallet->addAction(verifyMessageAction);

    QMenu *information = appMenuBar->addMenu(tr("Information"));
    information->addAction(openInfoAction);
    information->addAction(openTrafficAction);
    information->addAction(stakeReportAction);

    QMenu *help = appMenuBar->addMenu(tr("&Help"));
    help->addAction(openRPCConsoleAction);
    help->addSeparator();
    help->addAction(aboutAction);
    help->addAction(aboutQtAction);

    // QString ss("QMenuBar::item { background-color: #effbef; color: black }"); 
    // appMenuBar->setStyleSheet(ss);
}

void BitcoinGUI::createToolBars()
{
    QToolBar *toolbar = addToolBar(tr("Tabs toolbar"));
    toolbar->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    toolbar->addAction(overviewAction);
    toolbar->addAction(sendCoinsAction);
    toolbar->addAction(receiveCoinsAction);
    toolbar->addAction(historyAction);
    toolbar->addAction(addressBookAction);

    QToolBar *toolbar2 = addToolBar(tr("Actions toolbar"));
    toolbar2->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    toolbar2->addAction(blockAction);
    toolbar2->addAction(openRPCConsoleAction);
    toolbar2->addAction(exportAction);
}

void BitcoinGUI::setClientModel(ClientModel *clientModel)
{
    this->clientModel = clientModel;
    if(clientModel)
    {
        // Replace some strings and icons, when using the testnet
        if(clientModel->isTestNet())
        {
            setWindowTitle(windowTitle() + QString(" ") + tr("[testnet]"));
#ifndef Q_OS_MAC
            qApp->setWindowIcon(QIcon(":icons/bitcoin_testnet"));
            setWindowIcon(QIcon(":icons/bitcoin_testnet"));
#else
            MacDockIconHandler::instance()->setIcon(QIcon(":icons/bitcoin_testnet"));
#endif
            if(trayIcon)
            {
                trayIcon->setToolTip(tr("Truckcoin client") + QString(" ") + tr("[testnet]"));
                trayIcon->setIcon(QIcon(":/icons/toolbar_testnet"));
                toggleHideAction->setIcon(QIcon(":/icons/toolbar_testnet"));
            }

            aboutAction->setIcon(QIcon(":/icons/toolbar_testnet"));
        }
		
        // Create system tray menu (or setup the dock menu) that late to prevent users from calling actions, 
        // while the client has not yet fully loaded 
        if(trayIcon) 
            createTrayIconMenu(); 

        // Keep up to date with client
        setNumConnections(clientModel->getNumConnections());
        connect(clientModel, SIGNAL(numConnectionsChanged(int)), this, SLOT(setNumConnections(int)));

        setNumBlocks(clientModel->getNumBlocks(), clientModel->getNumBlocksOfPeers());
        connect(clientModel, SIGNAL(numBlocksChanged(int,int)), this, SLOT(setNumBlocks(int,int)));

        // Report errors from network/worker thread
        connect(clientModel, SIGNAL(message(QString,QString,unsigned int)), this, SLOT(message(QString,QString,unsigned int)));

        rpcConsole->setClientModel(clientModel);
        addressBookPage->setOptionsModel(clientModel->getOptionsModel());
        receiveCoinsPage->setOptionsModel(clientModel->getOptionsModel());
    }
}

void BitcoinGUI::setWalletModel(WalletModel *walletModel)
{
    this->walletModel = walletModel;
    if(walletModel)
    {
        // Report errors from wallet thread
        connect(walletModel, SIGNAL(message(QString,QString,unsigned int)), this, SLOT(message(QString,QString,unsigned int)));

        // Put transaction list in tabs
        transactionView->setModel(walletModel);

        overviewPage->setModel(walletModel);
        addressBookPage->setModel(walletModel->getAddressTableModel());
        receiveCoinsPage->setModel(walletModel->getAddressTableModel());
        sendCoinsPage->setModel(walletModel);
        signVerifyMessageDialog->setModel(walletModel);

        setEncryptionStatus(walletModel->getEncryptionStatus());
        connect(walletModel, SIGNAL(encryptionStatusChanged(int)), this, SLOT(setEncryptionStatus(int)));

        // Balloon pop-up for new transaction
        connect(walletModel->getTransactionTableModel(), SIGNAL(rowsInserted(QModelIndex,int,int)),
                this, SLOT(incomingTransaction(QModelIndex,int,int)));

        // Ask for passphrase if needed
        connect(walletModel, SIGNAL(requireUnlock()), this, SLOT(unlockWallet()));
    }
}

void BitcoinGUI::createTrayIcon()
{
#ifndef Q_OS_MAC
    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setToolTip(tr("Truckcoin client"));
    trayIcon->setIcon(QIcon(":/icons/toolbar"));
    trayIcon->show(); 
#endif 
 
    notificator = new Notificator(qApp->applicationName(), trayIcon); 
} 
 
void BitcoinGUI::createTrayIconMenu() 
{ 
    QMenu *trayIconMenu; 
#ifndef Q_OS_MAC 
    trayIconMenu = new QMenu(this); 
    trayIcon->setContextMenu(trayIconMenu); 
    connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
            this, SLOT(trayIconActivated(QSystemTrayIcon::ActivationReason)));
#else
    // Note: On Mac, the dock icon is used to provide the tray's functionality.
    MacDockIconHandler *dockIconHandler = MacDockIconHandler::instance();
    trayIconMenu = dockIconHandler->dockMenu();
#endif

    // Configuration of the tray icon (or dock icon) icon menu
    trayIconMenu->addAction(toggleHideAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(sendCoinsAction);
    trayIconMenu->addAction(receiveCoinsAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(signMessageAction);
    trayIconMenu->addAction(verifyMessageAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(optionsAction);
    trayIconMenu->addAction(openRPCConsoleAction);
#ifndef Q_OS_MAC // This is built-in on Mac
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(quitAction);
#endif
}

#ifndef Q_OS_MAC
void BitcoinGUI::trayIconActivated(QSystemTrayIcon::ActivationReason reason)
{
    if(reason == QSystemTrayIcon::Trigger)
    {
        // Click on system tray icon triggers show/hide of the main window
        toggleHideAction->trigger();
    }
}
#endif

void BitcoinGUI::optionsClicked()
{
    if(!clientModel || !clientModel->getOptionsModel())
        return;
    OptionsDialog dlg;
    dlg.setModel(clientModel->getOptionsModel());
    dlg.exec();
}

void BitcoinGUI::aboutClicked()
{
    AboutDialog dlg;
    dlg.setModel(clientModel);
    dlg.exec();
}

void BitcoinGUI::lockIconClicked() 
{ 
    if(!walletModel) 
        return; 
 
    if(walletModel->getEncryptionStatus() == WalletModel::Locked) 
        unlockWalletForMint(); 
} 

// Stake report dialog
void BitcoinGUI::stakeReportClicked()
{
    static StakeReportDialog dlg;
    dlg.setModel(walletModel);
    dlg.show();
}

void BitcoinGUI::setNumConnections(int count)
{
    QString icon;
    switch(count)
    {
    case 0: icon = ":/icons/connect_0"; break;
    case 1: case 2: case 3: icon = ":/icons/connect_1"; break;
    case 4: case 5: case 6: icon = ":/icons/connect_2"; break;
    case 7: case 8: case 9: icon = ":/icons/connect_3"; break;
    default: icon = ":/icons/connect_4"; break;
    }
    labelConnectionsIcon->setPixmap(QIcon(icon).pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
    labelConnectionsIcon->setToolTip(tr("%n active connection(s) to Truckcoin network", "", count));
}

void BitcoinGUI::setNumBlocks(int count, int nTotalBlocks)
{

    // Prevent orphan statusbar messages (e.g. hover Quit in main menu, wait until chain-sync starts -> garbelled text)
    statusBar()->clearMessage();

    // don't show / hide progress bar and its label if we have no connection to the network
    enum BlockSource blockSource = clientModel ? clientModel->getBlockSource() : BLOCK_SOURCE_NONE;
    if (blockSource == BLOCK_SOURCE_NONE || (blockSource == BLOCK_SOURCE_NETWORK && clientModel->getNumConnections() == 0))
    {
        progressBarLabel->setVisible(false);
        progressBar->setVisible(false);

        return;
    }

    QString strStatusBarWarnings = clientModel->getStatusBarWarnings();
    QString tooltip;
    
    QString importText;
    switch (blockSource) {
    case BLOCK_SOURCE_NONE:
    case BLOCK_SOURCE_NETWORK:
        importText = tr("Synchronizing with network...");
    case BLOCK_SOURCE_DISK:
        importText = tr("Importing blocks from disk...");
    case BLOCK_SOURCE_REINDEX:
        importText = tr("Reindexing blocks on disk...");
    }

    if(count < nTotalBlocks)
    {
        int nRemainingBlocks = nTotalBlocks - count;
        float nPercentageDone = count / (nTotalBlocks * 0.01f);

        if (strStatusBarWarnings.isEmpty())
        {
            progressBarLabel->setText(importText);
            progressBarLabel->setVisible(true);
            progressBar->setFormat(tr("~%n block(s) remaining", "", nRemainingBlocks));
            progressBar->setMaximum(nTotalBlocks);
            progressBar->setValue(count);
            progressBar->setVisible(true);
        }

        tooltip = tr("Processed %1 of %2 blocks of transaction history (%3% done).").arg(count).arg(nTotalBlocks).arg(nPercentageDone, 0, 'f', 2);
    }
    else
    {
        if (strStatusBarWarnings.isEmpty())
            progressBarLabel->setVisible(false);

        progressBar->setVisible(false);
        tooltip = tr("Processed %1 blocks of transaction history.").arg(count);
    }

    // Override progressBarLabel text and hide progress bar, when we have warnings to display
    if (!strStatusBarWarnings.isEmpty())
    {
        progressBarLabel->setText(strStatusBarWarnings);
        progressBarLabel->setVisible(true);
        progressBar->setVisible(false);
    }

    tooltip = tr("Current difficulty is %1.").arg(clientModel->GetDifficulty()) + QString("<br>") + tooltip;

    QDateTime lastBlockDate = clientModel->getLastBlockDate();
    int secs = lastBlockDate.secsTo(QDateTime::currentDateTime());
    QString text;

    // Represent time from last generated block in human readable text
    if(secs <= 0)
    {
        // Fully up to date. Leave text empty.
    }
    else if(secs < 60)
    {
        text = tr("%n second(s) ago","",secs);
    }
    else if(secs < 60*60)
    {
        text = tr("%n minute(s) ago","",secs/60);
    }
    else if(secs < 24*60*60)
    {
        text = tr("%n hour(s) ago","",secs/(60*60));
    }
    else
    {
        text = tr("%n day(s) ago","",secs/(60*60*24));
    }

    // Set icon state: spinning if catching up, tick otherwise
    if(secs < 90*60 && count >= nTotalBlocks)
    {
        tooltip = tr("Up to date") + QString(".<br>") + tooltip;
        labelBlocksIcon->setPixmap(QIcon(":/icons/synced").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));

        overviewPage->showOutOfSyncWarning(false);
    }
    else
    {
        tooltip = tr("Catching up...") + QString("<br>") + tooltip;
        labelBlocksIcon->setMovie(syncIconMovie);
        syncIconMovie->start();

        overviewPage->showOutOfSyncWarning(true);
    }

    if(!text.isEmpty())
    {
        tooltip += QString("<br>");
        tooltip += tr("Last received block was generated %1.").arg(text);
    }

    // Don't word-wrap this (fixed-width) tooltip
    tooltip = QString("<nobr>") + tooltip + QString("</nobr>");

    labelBlocksIcon->setToolTip(tooltip);
    progressBarLabel->setToolTip(tooltip);
    progressBar->setToolTip(tooltip);
}

void BitcoinGUI::message(const QString &title, const QString &message, unsigned int style)
{
  QString strTitle = tr("Truckcoin") + " - ";
  // Default to information icon
  int nMBoxIcon = QMessageBox::Information;
  int nNotifyIcon = Notificator::Information;

  // Check for usage of predefined title
  switch (style) {
  case CClientUIInterface::MSG_ERROR:
      strTitle += tr("Error");
      break;
  case CClientUIInterface::MSG_WARNING:
      strTitle += tr("Warning");
      break;
  case CClientUIInterface::MSG_INFORMATION:
      strTitle += tr("Information");
      break;
  default:
      strTitle += title; // Use supplied title
  }

  // Check for error/warning icon
  if (style & CClientUIInterface::ICON_ERROR) {
      nMBoxIcon = QMessageBox::Critical;
     nNotifyIcon = Notificator::Critical;
 }
  else if (style & CClientUIInterface::ICON_WARNING) {
      nMBoxIcon = QMessageBox::Warning;
      nNotifyIcon = Notificator::Warning;
  }

  // Display message
  if (style & CClientUIInterface::MODAL) {
      // Check for buttons, use OK as default, if none was supplied
      QMessageBox::StandardButton buttons;
      if (!(buttons = (QMessageBox::StandardButton)(style & CClientUIInterface::BTN_MASK)))
          buttons = QMessageBox::Ok;

      QMessageBox mBox((QMessageBox::Icon)nMBoxIcon, strTitle, message, buttons);
     mBox.exec();
  }
  else
     notificator->notify((Notificator::Class)nNotifyIcon, strTitle, message);
}

void BitcoinGUI::changeEvent(QEvent *e)
{
    QMainWindow::changeEvent(e);
#ifndef Q_OS_MAC // Ignored on Mac
    if(e->type() == QEvent::WindowStateChange)
    {
        if(clientModel && clientModel->getOptionsModel()->getMinimizeToTray())
        {
            QWindowStateChangeEvent *wsevt = static_cast<QWindowStateChangeEvent*>(e);
            if(!(wsevt->oldState() & Qt::WindowMinimized) && isMinimized())
            {
                QTimer::singleShot(0, this, SLOT(hide()));
                e->ignore();
            }
        }
    }
#endif
}

void BitcoinGUI::closeEvent(QCloseEvent *event)
{
    if(clientModel)
    {
#ifndef Q_OS_MAC // Ignored on Mac
        if(!clientModel->getOptionsModel()->getMinimizeToTray() &&
           !clientModel->getOptionsModel()->getMinimizeOnClose())
        {
            qApp->quit();
        }
#endif
    }
    QMainWindow::closeEvent(event);
}

void BitcoinGUI::askFee(qint64 nFeeRequired, bool *payFee)
{
    QString strMessage =
        tr("This transaction is over the size limit.  You can still send it for a fee of %1. "
          "This fee will be destroyed, which will help keep the inflation rate low.\n"
          "Do you want to pay the fee?").arg(
                BitcoinUnits::formatWithUnit(BitcoinUnits::BTC, nFeeRequired));
    QMessageBox::StandardButton retval = QMessageBox::question(
          this, tr("Confirm transaction fee"), strMessage,
          QMessageBox::Yes|QMessageBox::Cancel, QMessageBox::Yes);
    *payFee = (retval == QMessageBox::Yes);
}

void BitcoinGUI::incomingTransaction(const QModelIndex & parent, int start, int end)
{
    if(!walletModel || !clientModel)
        return;
    TransactionTableModel *ttm = walletModel->getTransactionTableModel();
    qint64 amount = ttm->index(start, TransactionTableModel::Amount, parent)
                    .data(Qt::EditRole).toULongLong();
    if(!clientModel->inInitialBlockDownload())
    {
        // On new transaction, make an info balloon
        // Unless the initial block download is in progress, to prevent balloon-spam
        QString date = ttm->index(start, TransactionTableModel::Date, parent)
                        .data().toString();
        QString type = ttm->index(start, TransactionTableModel::Type, parent)
                        .data().toString();
        QString address = ttm->index(start, TransactionTableModel::ToAddress, parent)
                        .data().toString();
        QIcon icon = qvariant_cast<QIcon>(ttm->index(start,
                            TransactionTableModel::ToAddress, parent)
                        .data(Qt::DecorationRole));

        message((amount)<0 ? tr("Sent transaction") : tr("Incoming transaction"), 
           tr("Date: %1\n" 
              "Amount: %2\n" 
              "Type: %3\n" 
              "Address: %4\n") 
                .arg(date) 
                .arg(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), amount, true)) 
                .arg(type) 
                .arg(address), CClientUIInterface::MSG_INFORMATION); 
    }
}

void BitcoinGUI::gotoOverviewPage()
{
    overviewAction->setChecked(true);
    centralWidget->setCurrentWidget(overviewPage);

    exportAction->setEnabled(false);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
}

void BitcoinGUI::gotoHistoryPage()
{
    historyAction->setChecked(true);
    centralWidget->setCurrentWidget(transactionsPage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
    connect(exportAction, SIGNAL(triggered()), transactionView, SLOT(exportClicked()));
}

void BitcoinGUI::gotoAddressBookPage()
{
    addressBookAction->setChecked(true);
    centralWidget->setCurrentWidget(addressBookPage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
    connect(exportAction, SIGNAL(triggered()), addressBookPage, SLOT(exportClicked()));
}

void BitcoinGUI::gotoBlockBrowser(QString transactionId)
{
	if(!transactionId.isEmpty())
		blockBrowser->setTransactionId(transactionId);
	
	blockBrowser->show();
}

void BitcoinGUI::gotoReceiveCoinsPage()
{
    receiveCoinsAction->setChecked(true);
    centralWidget->setCurrentWidget(receiveCoinsPage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
    connect(exportAction, SIGNAL(triggered()), receiveCoinsPage, SLOT(exportClicked()));
}

void BitcoinGUI::gotoSendCoinsPage()
{
    sendCoinsAction->setChecked(true);
    centralWidget->setCurrentWidget(sendCoinsPage);

    exportAction->setEnabled(false);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
}

void BitcoinGUI::gotoSignMessageTab(QString addr)
{
    // call show() in showTab_SM()
    signVerifyMessageDialog->showTab_SM(true);

    if(!addr.isEmpty())
        signVerifyMessageDialog->setAddress_SM(addr);
}

void BitcoinGUI::gotoVerifyMessageTab(QString addr)
{
    // call show() in showTab_VM()
    signVerifyMessageDialog->showTab_VM(true);

    if(!addr.isEmpty())
        signVerifyMessageDialog->setAddress_VM(addr);
}

void BitcoinGUI::dragEnterEvent(QDragEnterEvent *event)
{
    // Accept only URIs
    if(event->mimeData()->hasUrls())
        event->acceptProposedAction();
}

void BitcoinGUI::dropEvent(QDropEvent *event)
{
    if(event->mimeData()->hasUrls())
    {
        int nValidUrisFound = 0;
        QList<QUrl> uris = event->mimeData()->urls();
        foreach(const QUrl &uri, uris)
        {
            if (sendCoinsPage->handleURI(uri.toString()))
                nValidUrisFound++;
        }

        // if valid URIs were found
        if (nValidUrisFound)
            gotoSendCoinsPage();
        else
            message(tr("URI handling"), tr("URI can not be parsed! This can be caused by an invalid Truckcoin address or malformed URI parameters."), 
                    CClientUIInterface::ICON_WARNING); 
    }

    event->acceptProposedAction();
}

void BitcoinGUI::handleURI(QString strURI)
{
    // URI has to be valid
    if (sendCoinsPage->handleURI(strURI))
    {
        showNormalIfMinimized();
        gotoSendCoinsPage();
    }
    else
        message(tr("URI handling"), tr("URI can not be parsed! This can be caused by an invalid Truckcoin address or malformed URI parameters."), 
                CClientUIInterface::ICON_WARNING); 
}

void BitcoinGUI::setEncryptionStatus(int status)
{
    switch(status)
    {
    case WalletModel::Unencrypted:
        labelEncryptionIcon->hide();
        encryptWalletAction->setChecked(false);
        unlockWalletforposAction->setChecked(false);
        unlockWalletAction->setChecked(false);
        lockWalletAction->setChecked(false);
        encryptWalletAction->setEnabled(true);
        unlockWalletforposAction->setEnabled(false);
        unlockWalletAction->setEnabled(false);
        lockWalletAction->setEnabled(false);
        changePassphraseAction->setEnabled(false);
        disconnect(labelEncryptionIcon,SIGNAL(clicked()), this, SLOT(lockIconClicked()));labelEncryptionIcon->setToolTip(tr("Wallet is <b>not encrypted</b> and currently <b>unlocked</b>"));

        break;
    case WalletModel::Unlocked:
        labelEncryptionIcon->show();
        labelEncryptionIcon->setPixmap(QIcon(":/icons/lock_open").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
        labelEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>unlocked</b>"));
        encryptWalletAction->setChecked(true);
        unlockWalletforposAction->setChecked(true);
        unlockWalletAction->setChecked(true);
        lockWalletAction->setChecked(false);
        encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
        unlockWalletforposAction->setEnabled(false);
        unlockWalletAction->setEnabled(false);
        lockWalletAction->setEnabled(true);
        changePassphraseAction->setEnabled(true);
        disconnect(labelEncryptionIcon,SIGNAL(clicked()), this, SLOT(lockIconClicked()));
        break;
    case WalletModel::Locked:
        labelEncryptionIcon->show();
        labelEncryptionIcon->setPixmap(QIcon(":/icons/lock_closed").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
        labelEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>locked</b>"));
        encryptWalletAction->setChecked(true);
        unlockWalletforposAction->setChecked(false);
        unlockWalletAction->setChecked(false);
        lockWalletAction->setChecked(true);
        encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
        unlockWalletforposAction->setEnabled(true);
        unlockWalletAction->setEnabled(true);
        lockWalletAction->setEnabled(false);
        changePassphraseAction->setEnabled(true);
        connect(labelEncryptionIcon,SIGNAL(clicked()), this, SLOT(lockIconClicked()));
        break;
    }
}

void BitcoinGUI::encryptWallet(bool status)
{
    if(!walletModel)
        return;
    AskPassphraseDialog dlg(status ? AskPassphraseDialog::Encrypt:
                                     AskPassphraseDialog::Decrypt, this);
    dlg.setModel(walletModel);
    dlg.exec();

    setEncryptionStatus(walletModel->getEncryptionStatus());
}

void BitcoinGUI::checkWallet() 
{ 
    int nMismatchSpent; 
    int64_t nBalanceInQuestion; 
    int nOrphansFound; 
 
    if(!walletModel) 
        return; 
 
    // Check the wallet as requested by user 
    walletModel->checkWallet(nMismatchSpent, nBalanceInQuestion, nOrphansFound); 
 
    if (nMismatchSpent == 0 && nOrphansFound == 0) 
        message(tr("Check Wallet Information"), 
                tr("Wallet passed integrity test!\n" 
                   "Nothing found to fix.") 
                  ,CClientUIInterface::MSG_INFORMATION); 
  else 
       message(tr("Check Wallet Information"), 
               tr("Wallet failed integrity test!\n\n" 
                  "Mismatched coin(s) found: %1.\n" 
                  "Amount in question: %2.\n" 
                  "Orphans found: %3.\n\n" 
                  "Please backup wallet and run repair wallet.\n") 
                        .arg(nMismatchSpent) 
                        .arg(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), nBalanceInQuestion,true)) 
                        .arg(nOrphansFound) 
                 ,CClientUIInterface::MSG_WARNING); 
} 
 
void BitcoinGUI::repairWallet() 
{ 
    int nMismatchSpent; 
    int64_t nBalanceInQuestion; 
    int nOrphansFound; 
 
    if(!walletModel) 
        return; 
 
    // Repair the wallet as requested by user 
    walletModel->repairWallet(nMismatchSpent, nBalanceInQuestion, nOrphansFound); 
 
    if (nMismatchSpent == 0 && nOrphansFound == 0) 
       message(tr("Repair Wallet Information"), 
               tr("Wallet passed integrity test!\n" 
                  "Nothing found to fix.") 
                ,CClientUIInterface::MSG_INFORMATION); 
    else 
       message(tr("Repair Wallet Information"), 
               tr("Wallet failed integrity test and has been repaired!\n" 
                  "Mismatched coin(s) found: %1\n" 
                  "Amount affected by repair: %2\n" 
                  "Orphans removed: %3\n") 
                        .arg(nMismatchSpent) 
                        .arg(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), nBalanceInQuestion,true)) 
                        .arg(nOrphansFound) 
                  ,CClientUIInterface::MSG_WARNING); 
} 

void BitcoinGUI::backupWallet()
{
#if QT_VERSION < 0x050000
    QString saveDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
#else 
	QString saveDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation); 
#endif 

    QString filename = QFileDialog::getSaveFileName(this, tr("Backup Wallet"), saveDir, tr("Wallet Data (*.dat)"));
    if(!filename.isEmpty()) {
        if(!walletModel->backupWallet(filename)) {
QMessageBox::warning(this, tr("Backup Failed"), tr("There was an error trying to save the wallet data to the new location."));
        }
    }
}

void BitcoinGUI::dumpWallet()
{
   if(!walletModel)
      return;

   WalletModel::UnlockContext ctx(walletModel->requestUnlock());
   if(!ctx.isValid())
   {
       // Unlock wallet failed or was cancelled
       return;
   }

#if QT_VERSION < 0x050000
    QString saveDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
#else
    QString saveDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
#endif
    QString filename = QFileDialog::getSaveFileName(this, tr("Export Wallet"), saveDir, tr("Wallet Text (*.txt)"));
    if(!filename.isEmpty()) {
        if(!walletModel->dumpWallet(filename)) {
            message(tr("Export Failed"),
                         tr("There was an error trying to save the wallet's keys to your location.\n"
                           "Keys were not saved")
                      ,CClientUIInterface::MSG_ERROR);
        }
        else
            message(tr("Export Successful"),
                       tr("Keys were saved to:\n %1")
                       .arg(filename)
                     ,CClientUIInterface::MSG_INFORMATION);
    }
}

void BitcoinGUI::importWallet()
{
   if(!walletModel)
      return;

   WalletModel::UnlockContext ctx(walletModel->requestUnlock());
   if(!ctx.isValid())
   {
       // Unlock wallet failed or was cancelled
       return;
   }

#if QT_VERSION < 0x050000
    QString openDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
#else
    QString openDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
#endif
    QString filename = QFileDialog::getOpenFileName(this, tr("Import Wallet"), openDir, tr("Wallet Text (*.txt)"));
    if(!filename.isEmpty()) {
        if(!walletModel->importWallet(filename)) {
            message(tr("Import Failed"),
                         tr("There was an error trying to import the file's keys into your wallet.\n"
                            "Some or all keys were not imported from walletfile: %1")
                         .arg(filename)
                      ,CClientUIInterface::MSG_ERROR);
        }
        else
            message(tr("Import Successful"),
                      tr("Keys %1, were imported into wallet.")
                      .arg(filename)
                      ,CClientUIInterface::MSG_INFORMATION);
    }
}
void BitcoinGUI::changePassphrase()
{
    AskPassphraseDialog dlg(AskPassphraseDialog::ChangePass, this);
    dlg.setModel(walletModel);
    dlg.exec();
}

void BitcoinGUI::unlockWallet()
{
    if(!walletModel)
        return;
    // Unlock wallet when requested by wallet model
    if(walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        dlg.exec();
    }
}

void BitcoinGUI::unlockWalletForMint() 
{ 
    if(!walletModel) 
        return; 

    // Unlock wallet when requested by user 
    if(walletModel->getEncryptionStatus() == WalletModel::Locked) 
{ 
      AskPassphraseDialog dlg(AskPassphraseDialog::UnlockForMint, this); 
        dlg.setModel(walletModel); 
        dlg.exec(); 
 
        // Only show message if unlock is sucessfull. 
        if(walletModel->getEncryptionStatus() == WalletModel::Unlocked) 
          message(tr("Unlock Wallet Information"), 
                  tr("Wallet has been unlocked. \n" 
                     "Proof of Stake has started.\n") 
                  ,CClientUIInterface::MSG_INFORMATION); 
    } 
} 

void BitcoinGUI::lockWallet() 
{ 
    if(!walletModel) 
        return; 
 
    // Lock wallet when requested by user 
    if(walletModel->getEncryptionStatus() == WalletModel::Unlocked) 
        walletModel->setWalletLocked(true,"",true); 
 
    message(tr("Lock Wallet Information"), 
            tr("Wallet has been locked.\n" 
               "Proof of Stake has stopped.\n") 
            ,CClientUIInterface::MSG_INFORMATION); 
} 

// Enables or disables the internal stake miner;
// only sets the menu icon and text on the initial run 
void BitcoinGUI::stakeMinerToggle(bool fInitial) {
    bool fStakingInt = fStaking;

    if(fInitial) {
        fStakingInt = GetBoolArg("-staking", fStaking);
        fStakingInt = ~fStakingInt & 0x1;
    }

    if(fStakingInt) {
        if(!fInitial) fStaking = false;
        stakeMinerToggleAction->setIcon(QIcon(":/icons/staking_on"));
        stakeMinerToggleAction->setText(tr("&Enable PoS mining"));
    } else {
        if(!fInitial) fStaking = true;
        stakeMinerToggleAction->setIcon(QIcon(":/icons/staking_off"));
        stakeMinerToggleAction->setText(tr("&Disable PoS mining"));
    }

    if(!fInitial)
      updateMintingIcon();
}

void BitcoinGUI::showNormalIfMinimized(bool fToggleHidden)
{
    // activateWindow() (sometimes) helps with keyboard focus on Windows
    if (isHidden())
    {
        show();
        activateWindow();
    }
    else if (isMinimized())
    {
        showNormal();
        activateWindow();
    }
    else if (GUIUtil::isObscured(this))
    {
        raise();
        activateWindow();
    }
    else if(fToggleHidden)
        hide();
}

void BitcoinGUI::toggleHidden()
{
    showNormalIfMinimized(true);
}

void BitcoinGUI::updateMintingIcon()
{
    if  (!fStaking)
    {
        labelMintingIcon->setToolTip(tr("Not minting because staking is disabled."));
        labelMintingIcon->setEnabled(false);
    }
    else if (pwalletMain && pwalletMain->IsLocked())
    {
        labelMintingIcon->setToolTip(tr("Not minting because wallet is locked."));
        labelMintingIcon->setEnabled(false);
    }
    else if (vNodes.empty())
    {
        labelMintingIcon->setToolTip(tr("Not minting because wallet is offline."));
        labelMintingIcon->setEnabled(false);
    }

    else if (clientModel->getNumConnections() < 2 )
    {
        labelMintingIcon->setToolTip(tr("Not minting because wallet is still acquiring nodes."));
        labelMintingIcon->setEnabled(false);
    }

    else if (IsInitialBlockDownload() || clientModel->getNumBlocks() < clientModel->getNumBlocksOfPeers())
    {
        labelMintingIcon->setToolTip(tr("Not minting because wallet is syncing."));
        labelMintingIcon->setEnabled(false);
    }
    else if (!nWeight)
    {
        labelMintingIcon->setToolTip(tr("Not minting because you don't have mature coins.<br>Next block matures in %2 hours<br>Network weight is %1").arg(nNetworkWeight).arg(nHoursToMaturity));
        labelMintingIcon->setEnabled(false);
    }
    else if (nLastCoinStakeSearchInterval)
    {
        uint64_t nAccuracyAdjustment = 1; // this is a manual adjustment param if needed to make more accurate
        uint64_t nEstimateTime = nStakeTargetSpacing * nNetworkWeight / nWeight / nAccuracyAdjustment;

        uint64_t nRangeLow = nEstimateTime;
        uint64_t nRangeHigh = nEstimateTime * 1.5;
        QString text;
        if (nEstimateTime < 60)
        {
            text = tr("%1 - %2 seconds").arg(nRangeLow).arg(nRangeHigh);
        }
        else if (nEstimateTime < 60*60)
        {
            text = tr("%1 - %2 minutes").arg(nRangeLow / 60).arg(nRangeHigh / 60);
        }
        else if (nEstimateTime < 24*60*60)
        {
            text = tr("%1 - %2 hours").arg(nRangeLow / (60*60)).arg(nRangeHigh / (60*60));
        }
        else
        {
            text = tr("%1 - %2 days").arg(nRangeLow / (60*60*24)).arg(nRangeHigh / (60*60*24));
        }

        labelMintingIcon->setEnabled(true);
        labelMintingIcon->setToolTip(tr("Minting.<br>Your weight is %1.<br>Network weight is %2.<br>Expected time to earn reward is %3.").arg(nWeight).arg(nNetworkWeight).arg(text));
    }
    else
    {
        labelMintingIcon->setToolTip(tr("Not minting."));
        labelMintingIcon->setEnabled(false);
    }
}

void BitcoinGUI::updateMintingWeights()
{
    // Only update if we have the network's current number of blocks, or weight(s) are zero (fixes lagging GUI)
    if ((clientModel && clientModel->getNumBlocks() == clientModel->getNumBlocksOfPeers()) || !nWeight || !nNetworkWeight)
    {
        nWeight = 0;

        if (pwalletMain)
            pwalletMain->GetStakeWeight2(*pwalletMain, nMinMax, nMinMax, nWeight, nHoursToMaturity);

        nNetworkWeight = GetPoSKernelPS();
    }
}

WId BitcoinGUI::getMainWinId() const 
{ 
    return winId(); 
}

void BitcoinGUI::updateStyleSlot()
{
    updateStyle();
}

void BitcoinGUI::updateStyle()
{
    if (!fUseTruckcoinTheme)
        return;

    QString qssPath = QString::fromStdString( GetDataDir().string() ) + "/truckcoin.qss";

    QFile f( qssPath );

    if (!f.exists())
        writeDefaultStyleSheet( qssPath );

    if (!f.open(QFile::ReadOnly))
    {
        qDebug() << "failed to open style sheet";
        return;
    }

    qDebug() << "loading theme";
    qApp->setStyleSheet( f.readAll() );
}

void BitcoinGUI::writeDefaultStyleSheet(const QString &qssPath)
{
    qDebug() << "writing default style sheet";

    QFile qss( ":/text/stylesheet" );
    qss.open( QFile::ReadOnly );

    QFile f( qssPath );
    f.open( QFile::ReadWrite );
    f.write( qss.readAll() );
}
