#ifndef HAVOC_USERMANAGEMENTDIALOG_HPP
#define HAVOC_USERMANAGEMENTDIALOG_HPP

#include <global.hpp>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

class UserManagementDialog : public QDialog
{
public:
    explicit UserManagementDialog(QWidget* parent = nullptr);

private:
    void onCreateUserClicked();
    void onEditUserClicked();
    void onDeleteUserClicked();
    void onAssignAgentsClicked();
    void onRefreshClicked();
    void onUserSelectionChanged();
    void onNetworkReplyFinished();

private:
    void setupUi();
    void refreshUserList();
    void authenticateForHttpSession();
    void makeApiRequest(const QString& endpoint, const QString& method = "GET", const QJsonObject& data = QJsonObject());
    void handleAuthResponse(const QJsonDocument& doc);
    void handleUserListResponse(const QJsonDocument& doc);
    void handleDeleteResponse(const QJsonDocument& doc);
    void showErrorMessage(const QString& title, const QString& message);
    void showSuccessMessage(const QString& message);
    
    // Helper function to get user data by table row (handles sorting)
    QJsonObject getUserDataForRow(int row) const;
    
    // UI Components
    QVBoxLayout* mainLayout;
    QHBoxLayout* headerLayout;
    QHBoxLayout* actionButtonLayout;
    QHBoxLayout* utilityButtonLayout;
    QHBoxLayout* statusLayout;
    
    QLabel* statusLabel;
    
    QTableWidget* userTable;
    
    QPushButton* createUserButton;
    QPushButton* editUserButton;
    QPushButton* deleteUserButton;
    QPushButton* assignAgentsButton;
    QPushButton* refreshButton;
    QPushButton* closeButton;
    
    // Network
    QNetworkAccessManager* networkManager;
    QNetworkReply* currentReply;
    QString currentRequestType;
    QString sessionToken; // HTTP session token for API authentication
    
    // Data
    QJsonArray userData;
};

#endif // HAVOC_USERMANAGEMENTDIALOG_HPP
