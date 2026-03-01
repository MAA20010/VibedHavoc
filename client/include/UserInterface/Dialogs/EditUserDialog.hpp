#ifndef HAVOC_EDITUSERDDIALOG_HPP
#define HAVOC_EDITUSERDDIALOG_HPP

#include <global.hpp>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QRadioButton>
#include <QButtonGroup>
#include <QCheckBox>

class EditUserDialog : public QDialog
{
public:
    explicit EditUserDialog(const QJsonObject& userData, const QString& sessionToken, QWidget* parent = nullptr);

private slots:
    void onSaveClicked();
    void onCancelClicked();
    void onNetworkReplyFinished();
    void onPasswordVisibilityToggled();

private:
    void setupUi();
    void populateFields();
    void makeUpdateRequest();
    void showErrorMessage(const QString& title, const QString& message);
    void showSuccessMessage(const QString& message);
    bool validateInputs();
    
    // UI Components
    QVBoxLayout* mainLayout;
    QFormLayout* formLayout;
    QHBoxLayout* buttonLayout;
    QHBoxLayout* passwordLayout;
    
    QLabel* titleLabel;
    QLabel* usernameLabel;
    
    QLineEdit* usernameEdit;
    QLineEdit* passwordEdit;
    QButtonGroup* roleButtonGroup;
    QRadioButton* adminRadio;
    QRadioButton* operatorRadio;
    QRadioButton* agentOperatorRadio;
    QCheckBox* activeCheckBox;
    QPushButton* passwordVisibilityButton;
    
    QPushButton* saveButton;
    QPushButton* cancelButton;
    
    // Network
    QNetworkAccessManager* networkManager;
    QNetworkReply* currentReply;
    QString authToken;
    
    // Data
    QJsonObject originalUserData;
    QString originalUsername;
};

#endif // HAVOC_EDITUSERDDIALOG_HPP
