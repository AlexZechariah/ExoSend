/**
 * @file TrayIcon.h
 * @brief System tray icon handler for ExoSend
 *
 * This class manages the system tray icon, context menu,
 * and balloon notifications for the ExoSend application.
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#ifndef EXOSEND_QTUI_TRAYICON_H
#define EXOSEND_QTUI_TRAYICON_H

#include <QObject>
#include <QIcon>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>

// Forward declarations
class MainWindow;

/**
 * @class TrayIcon
 * @brief System tray icon manager
 *
 * This class wraps QSystemTrayIcon and provides:
 * - System tray icon with ExoSend logo
 * - Context menu (Open, Quit)
 * - Click/double-click handling
 * - Balloon notifications for events
 *
 * The tray icon allows the application to minimize to the system
 * tray instead of exiting, allowing it to continue receiving files
 * in the background.
 *
 * Usage:
 * ```cpp
 * TrayIcon* tray = new TrayIcon(mainWindow);
 * tray->show();
 * connect(tray, &TrayIcon::quitRequested, qApp, &QApplication::quit);
 * ```
 */
class TrayIcon : public QObject {
    Q_OBJECT

public:
    /**
     * @brief Constructor
     * @param mainWindow Pointer to main window (for show/hide)
     * @param parent Parent QObject
     *
     * The MainWindow pointer is stored but NOT owned.
     * The window must remain valid for the lifetime of this tray icon.
     */
    explicit TrayIcon(MainWindow* mainWindow, QObject* parent = nullptr);

    /**
     * @brief Destructor
     */
    ~TrayIcon() override;

    /**
     * @brief Show the tray icon
     */
    void show();

    /**
     * @brief Hide the tray icon
     */
    void hide();

    /**
     * @brief Display a balloon notification
     * @param title Notification title
     * @param message Notification message
     * @param duration Duration in milliseconds (default: 5000ms)
     *
     * Shows a balloon popup from the tray icon.
     * Note: Some systems may suppress balloon notifications.
     */
    void showMessage(const QString& title, const QString& message, int duration = 5000);

    /**
     * @brief Set the tooltip text
     * @param tip Tooltip text (shown on hover)
     */
    void setToolTip(const QString& tip);

    /**
     * @brief Set the tray icon
     * @param icon Icon to display
     */
    void setIcon(const QIcon& icon);

    /**
     * @brief Check if tray icon is visible
     * @return true if visible
     */
    bool isVisible() const { return m_trayIcon ? m_trayIcon->isVisible() : false; }

signals:
    /**
     * @brief Emitted when user clicks "Open" in context menu or double-clicks icon
     */
    void showWindowRequested();

    /**
     * @brief Emitted when user clicks "Quit" in context menu
     */
    void quitRequested();

private slots:
    /**
     * @brief Handle user activation of tray icon
     * @param reason Type of activation (click, double-click, etc.)
     */
    void onActivated(QSystemTrayIcon::ActivationReason reason);

    /**
     * @brief Handle "Open" menu action
     */
    void onShowWindow();

    /**
     * @brief Handle "Quit" menu action
     */
    void onQuit();

private:
    /**
     * @brief Create the context menu
     */
    void createMenu();

private:
    QSystemTrayIcon* m_trayIcon;  ///< Qt system tray icon
    MainWindow* m_mainWindow;     ///< Main window (not owned)
    QMenu* m_contextMenu;         ///< Context menu
    QAction* m_showAction;        ///< "Open" action
    QAction* m_quitAction;        ///< "Quit" action
};

#endif // EXOSEND_QTUI_TRAYICON_H
