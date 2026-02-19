/**
 * @file TrayIcon.cpp
 * @brief System tray icon handler implementation
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#include "exosend/QtUi/TrayIcon.h"
#include "exosend/QtUi/MainWindow.h"
#include <QApplication>
#include <iostream>  // For std::cerr
#include <thread>    // For std::this_thread::get_id()

// ========================================================================
// Constructor / Destructor
// ========================================================================

TrayIcon::TrayIcon(MainWindow* mainWindow, QObject* parent)
    : QObject(parent)
    , m_trayIcon(nullptr)
    , m_mainWindow(mainWindow)
    , m_contextMenu(nullptr)
    , m_showAction(nullptr)
    , m_quitAction(nullptr)
{
    // Create system tray icon
    m_trayIcon = new QSystemTrayIcon(this);

    // Create context menu
    createMenu();

    // Connect activation signal
    connect(m_trayIcon, &QSystemTrayIcon::activated,
            this, &TrayIcon::onActivated);

    // Set custom ExoSend icon
    setIcon(QIcon(":/assets/icon.png"));

    // Set default tooltip
    setToolTip("ExoSend - Ready");
}

TrayIcon::~TrayIcon()
{
}

// ========================================================================
// Public Methods
// ========================================================================

void TrayIcon::show()
{
    if (m_trayIcon) {
        m_trayIcon->show();
    }
}

void TrayIcon::hide()
{
    if (m_trayIcon) {
        m_trayIcon->hide();
    }
}

void TrayIcon::showMessage(const QString& title, const QString& message, int duration)
{
    if (m_trayIcon && m_trayIcon->supportsMessages()) {
        m_trayIcon->showMessage(title, message, QSystemTrayIcon::Information, duration);
    }
}

void TrayIcon::setToolTip(const QString& tip)
{
    if (m_trayIcon) {
        m_trayIcon->setToolTip(tip);
    }
}

void TrayIcon::setIcon(const QIcon& icon)
{
    if (m_trayIcon) {
        m_trayIcon->setIcon(icon);
    }
}

// ========================================================================
// Private Slots
// ========================================================================

void TrayIcon::onActivated(QSystemTrayIcon::ActivationReason reason)
{
    switch (reason) {
    case QSystemTrayIcon::Trigger:
        // Single click - toggle window visibility
        if (m_mainWindow) {
            if (m_mainWindow->isVisible()) {
                m_mainWindow->hide();
            } else {
                m_mainWindow->show();
                m_mainWindow->activateWindow();
                m_mainWindow->raise();
            }
        }
        break;

    case QSystemTrayIcon::DoubleClick:
        // Double click - show and activate window
        emit showWindowRequested();
        if (m_mainWindow) {
            m_mainWindow->show();
            m_mainWindow->activateWindow();
            m_mainWindow->raise();
        }
        break;

    case QSystemTrayIcon::MiddleClick:
        // Middle click - show window
        emit showWindowRequested();
        if (m_mainWindow) {
            m_mainWindow->show();
            m_mainWindow->activateWindow();
            m_mainWindow->raise();
        }
        break;

    default:
        break;
    }
}

void TrayIcon::onShowWindow()
{
    emit showWindowRequested();

    if (m_mainWindow) {
        m_mainWindow->show();
        m_mainWindow->activateWindow();
        m_mainWindow->raise();
    }
}

void TrayIcon::onQuit()
{
    emit quitRequested();
}

// ========================================================================
// Private Methods
// ========================================================================

void TrayIcon::createMenu()
{
    // Create context menu
    m_contextMenu = new QMenu();

    // "Open" action
    m_showAction = new QAction("Open", this);
    m_showAction->setIcon(qApp->style()->standardIcon(QStyle::SP_DialogOpenButton));
    connect(m_showAction, &QAction::triggered, this, &TrayIcon::onShowWindow);

    // Separator
    QAction* separator = new QAction(this);
    separator->setSeparator(true);

    // "Quit" action
    m_quitAction = new QAction("Quit", this);
    m_quitAction->setIcon(qApp->style()->standardIcon(QStyle::SP_DialogCancelButton));
    connect(m_quitAction, &QAction::triggered, this, &TrayIcon::onQuit);

    // Add to menu
    m_contextMenu->addAction(m_showAction);
    m_contextMenu->addAction(separator);
    m_contextMenu->addAction(m_quitAction);

    // Set menu on tray icon
    m_trayIcon->setContextMenu(m_contextMenu);
}
