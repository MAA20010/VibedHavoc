#ifndef HAVOC_AGENTASSIGNMENTDIALOG_HPP
#define HAVOC_AGENTASSIGNMENTDIALOG_HPP

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QListWidget>
#include <QPushButton>
#include <QLabel>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSslSocket>
#include <QSslConfiguration>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

namespace HavocNamespace::UserInterface::Dialogs {

    class AgentAssignmentDialog : public QDialog {
        Q_OBJECT

    public:
        explicit AgentAssignmentDialog(const QString& username, const QString& sessionToken, QWidget* parent = nullptr);
        ~AgentAssignmentDialog();

    private:
        void setupUi();
        void loadAgentLists();
        void makeApiRequest(const QString& endpoint, const QString& method, const QJsonObject& data = QJsonObject());
        void onNetworkReplyFinished();
        void showErrorMessage(const QString& title, const QString& message);
        
    private slots:
        void onAssignButtonClicked();
        void onRevokeButtonClicked();
        void onRefreshButtonClicked();
        void onAvailableAgentSelectionChanged();
        void onAssignedAgentSelectionChanged();

    private:
        // UI Components
        QVBoxLayout*           mainLayout;
        QHBoxLayout*           listsLayout;
        QHBoxLayout*           buttonLayout;
        QHBoxLayout*           actionButtonLayout;
        
        QLabel*                statusLabel;
        QLabel*                availableLabel;
        QLabel*                assignedLabel;
        
        QListWidget*           availableAgentsList;
        QListWidget*           assignedAgentsList;
        
        QPushButton*           assignButton;
        QPushButton*           revokeButton;
        QPushButton*           refreshButton;
        QPushButton*           closeButton;
        
        // Network
        QNetworkAccessManager* networkManager;
        QNetworkReply*         currentReply;
        QString                sessionToken;
        QString                targetUsername;
        QString                currentRequestType;  // "load_available", "load_assigned", "assign", "revoke"
    };

} // namespace HavocNamespace::UserInterface::Dialogs

#endif // HAVOC_AGENTASSIGNMENTDIALOG_HPP

