#ifndef HAVOC_SERVERLOOTWIDGET_H
#define HAVOC_SERVERLOOTWIDGET_H

#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QStackedWidget>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QWidget>
#include <QLabel>
#include <QScrollArea>
#include <QProgressBar>
#include <QTreeWidget>

// Reuse ImageLabel from LootWidget
class ImageLabel;

class ServerLootWidget : public QWidget
{
    Q_OBJECT

public:
    enum {
        LOOT_IMAGE,
        LOOT_FILE,
    };

    typedef struct
    {
        int     Type;
        QString AgentID;
        QString RelativePath;          // Server-side relative path
        QString Operator;              // Who created it
        QString ExternalIP;            // Agent context
        QString Hostname;              // Agent context
        QString Username;              // Agent context
        QString SessionID;             // Session identifier
        qint64  FileSize;
        QString Timestamp;
        bool    Downloaded;            // Local cache status
        QByteArray CachedData;         // Locally cached file data

        struct
        {
            QString     Name;
            QString     Date;
            QString     Size;
        } Display;

    } ServerLootData;
    
    std::vector<ServerLootData> ServerLootItems;

    QGridLayout*    gridLayout;

    QLabel*         LabelShow;
    QLabel*         LabelAgentID;
    QLabel*         LabelStatus;

    QComboBox*      ComboShow;
    QComboBox*      ComboAgentID;

    QTableWidget*   ScreenshotTable;
    QTableWidget*   DownloadTable;

    QMenu*          ScreenshotMenu;
    QAction*        ScreenshotActionDownload;
    QAction*        ScreenshotActionDelete;
    QAction*        ScreenshotActionRefresh;

    QMenu*          DownloadMenu;
    QAction*        DownloadActionDownload;
    QAction*        DownloadActionDelete;
    QAction*        DownloadActionRefresh;

    QSpacerItem*    horizontalSpacer;
    QStackedWidget* StackWidget;
    QWidget*        Screenshots;
    QGridLayout*    gridLayout_2;
    QSplitter*      splitter;
    ImageLabel*     ScreenshotImage;
    QWidget*        Downloads;
    QGridLayout*    gridLayout_3;

    QSpacerItem*    horizontalSpacer_2;

    ServerLootWidget();
    void Reload();
    void ClearLoot();

    void AddSessionSection( const QString& DemonID );
    void AddServerSideScreenshot( const QString& DemonID, const QString& Name, const QString& Date, const QString& RelativePath, const QString& Operator, const QString& ExternalIP, const QString& Hostname, const QString& SessionID );
    void AddServerSideDownload( const QString& DemonID, const QString& Name, const QString& Size, const QString& Date, const QString& RelativePath, const QString& Operator, const QString& ExternalIP, const QString& Hostname, const QString& SessionID );
    
    void RequestServerLootFile( const QString& AgentID, const QString& RelativePath );
    void RequestLootSync();
    void RequestDeleteLootFile( const QString& AgentID, const QString& RelativePath );
    void UpdateServerLootFileResponse( const QString& AgentID, const QString& RelativePath, const QByteArray& FileData );

    void ScreenshotTableAdd( const QString& Name, const QString& Date, const QString& Operator, const QString& ExternalIP, const QString& Hostname, const QString& SessionID );
    void DownloadTableAdd( const QString& Name, const QString& Size, const QString& Date, const QString& Operator, const QString& ExternalIP, const QString& Hostname, const QString& SessionID );

private Q_SLOTS:
    void onAgentChange( const QString& text );
    void onShowChange( const QString& text );
    void onScreenshotTableClick( const QModelIndex &index );
    void onDownloadTableClick( const QModelIndex &index );
    void onScreenshotTableCtx( const QPoint &pos );
    void onDownloadTableCtx( const QPoint &pos );
    void onScreenshotDownload();
    void onDownloadDownload();
    void onScreenshotDelete();
    void onDownloadDelete();
    void onRefresh();
};

#endif
