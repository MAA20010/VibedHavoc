#ifndef HAVOC_CREATEUSERDIALOG_HPP
#define HAVOC_CREATEUSERDIALOG_HPP

#include <global.hpp>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCryptographicHash>
#include <QRadioButton>
#include <QButtonGroup>
#include <QCheckBox>

class CreateUserDialog : public QDialog
{
public:
    explicit CreateUserDialog(const QString& sessionToken, QWidget* parent = nullptr);

private:
    void onCreateClicked();
    void onCancelClicked();
    void onPasswordVisibilityToggled();
    void onNetworkReplyFinished();

private:
    void setupUi();
    bool validateInputs();
    void makeCreateRequest();
    void showErrorMessage(const QString& title, const QString& message);
    void showSuccessMessage(const QString& message);
    
    // Network
    QNetworkAccessManager* networkManager;
    QNetworkReply* currentReply;
    QString authToken;
    
    // UI Components
    QVBoxLayout* mainLayout;
    QFormLayout* formLayout;
    QHBoxLayout* buttonLayout;
    QHBoxLayout* passwordLayout;
    QVBoxLayout* roleLayout;
    
    QLabel* titleLabel;
    
    QLineEdit* usernameEdit;
    QLineEdit* passwordEdit;
    QPushButton* passwordVisibilityButton;
    
    // Role selection with radio buttons (cleaner than dropdown)
    QButtonGroup* roleButtonGroup;
    QRadioButton* adminRadio;
    QRadioButton* operatorRadio;
    QRadioButton* agentOperatorRadio;
    
    QCheckBox* activeCheckBox;
    
    QPushButton* createButton;
    QPushButton* cancelButton;
};

#endif // HAVOC_CREATEUSERDIALOG_HPP
