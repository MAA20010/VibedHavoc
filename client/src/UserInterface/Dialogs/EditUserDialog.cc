#include <UserInterface/Dialogs/EditUserDialog.hpp>
#include <QCryptographicHash>
#include <QTimer>

EditUserDialog::EditUserDialog(const QJsonObject& userData, const QString& sessionToken, QWidget* parent)
    : QDialog(parent), originalUserData(userData), authToken(sessionToken)
{
    originalUsername = userData["username"].toString();
    networkManager = new QNetworkAccessManager(this);
    currentReply = nullptr;
    
    setupUi();
    populateFields();
    
    // Connect network manager
    connect(networkManager, &QNetworkAccessManager::finished, this, &EditUserDialog::onNetworkReplyFinished);
}

void EditUserDialog::setupUi()
{
    setWindowTitle("Edit User");
    setModal(true);
    setFixedSize(500, 480);
    setObjectName("EditUserDialog");
    
    // Apply modern Havoc dark theme styling with enhanced field design
    setStyleSheet(R"(
        QDialog#EditUserDialog {
            background-color: #2b2b2b;
            color: #ffffff;
            border: 2px solid #404040;
            border-radius: 8px;
        }
        
        QLabel {
            color: #ffffff;
            background-color: transparent;
            border: none;
            font-size: 13px;
        }
        
        QLabel#titleLabel {
            font-size: 18px;
            font-weight: bold;
            color: #61dafb;
            margin-bottom: 20px;
            border-bottom: 2px solid #404040;
            padding-bottom: 10px;
        }
        
        /* Remove outlines from container widgets */
        QWidget {
            background-color: transparent;
            border: none;
            outline: none;
        }
        
        QWidget#passwordWidget {
            background-color: transparent;
            border: none;
            outline: none;
        }
        
        /* Form layout styling */
        QFormLayout {
            background-color: transparent;
            border: none;
            outline: none;
        }
        
        /* Layout containers */
        QHBoxLayout, QVBoxLayout {
            background-color: transparent;
            border: none;
            outline: none;
        }
        
        /* Enhanced input field styling */
        QLineEdit {
            background-color: #383838;
            color: #ffffff;
            border: 2px solid #555555;
            border-radius: 8px;
            padding: 12px 15px;
            font-size: 14px;
            selection-background-color: #61dafb;
            selection-color: #000000;
        }
        
        QLineEdit:focus {
            border: 2px solid #61dafb;
            outline: none;
            background-color: #404040;
        }
        
        QLineEdit:hover {
            border: 2px solid #666666;
            background-color: #404040;
        }
        
        QLineEdit:disabled {
            background-color: #2a2a2a;
            color: #777777;
            border: 2px solid #404040;
        }
        
        /* Enhanced combo box styling */
        QComboBox {
            background-color: #383838;
            color: #ffffff;
            border: 2px solid #555555;
            border-radius: 8px;
            padding: 12px 15px;
            font-size: 14px;
            min-width: 150px;
        }
        
        QComboBox:focus {
            border: 2px solid #61dafb;
            outline: none;
            background-color: #404040;
        }
        
        QComboBox:hover {
            border: 2px solid #666666;
            background-color: #404040;
        }
        
        QComboBox::drop-down {
            border: none;
            background-color: #555555;
            width: 25px;
            border-top-right-radius: 6px;
            border-bottom-right-radius: 6px;
        }
        
        QComboBox::down-arrow {
            image: none;
            border-style: solid;
            border-width: 5px;
            border-color: #ffffff transparent transparent transparent;
            margin: 0px 6px;
        }
        
        /* Simplified dropdown list */
        QComboBox QAbstractItemView {
            background-color: #404040;
            color: #ffffff;
            border: 1px solid #606060;
            border-radius: 4px;
            selection-background-color: #61dafb;
            selection-color: #000000;
            outline: none;
            alternate-background-color: #383838;
        }
        
        QComboBox QAbstractItemView::item {
            padding: 10px 15px;
            border: none;
            background-color: transparent;
        }
        
        QComboBox QAbstractItemView::item:selected {
            background-color: #61dafb;
            color: #000000;
        }
        
        QComboBox QAbstractItemView::item:hover {
            background-color: #4a4a4a;
            color: #ffffff;
        }
        
        /* Enhanced checkbox styling */
        QCheckBox {
            color: #ffffff;
            font-size: 14px;
            spacing: 10px;
            background-color: transparent;
            border: none;
            outline: none;
        }
        
        QCheckBox:focus {
            outline: none;
            border: none;
        }
        
        QCheckBox::indicator {
            width: 20px;
            height: 20px;
            border: 2px solid #555555;
            border-radius: 4px;
            background-color: #383838;
        }
        
        QCheckBox::indicator:hover {
            border: 2px solid #61dafb;
            background-color: #404040;
        }
        
        QCheckBox::indicator:checked {
            background-color: #61dafb;
            border: 2px solid #61dafb;
            image: none;
        }
        
        QCheckBox::indicator:checked:hover {
            background-color: #4bc5e8;
            border: 2px solid #4bc5e8;
        }
        
        /* Radio button styling */
        QRadioButton {
            color: #ffffff;
            font-size: 14px;
            spacing: 10px;
            background-color: transparent;
            border: none;
            outline: none;
        }
        
        QRadioButton:focus {
            outline: none;
            border: none;
        }
        
        QRadioButton::indicator {
            width: 18px;
            height: 18px;
            border: 2px solid #555555;
            border-radius: 9px;
            background-color: #383838;
        }
        
        QRadioButton::indicator:hover {
            border: 2px solid #61dafb;
            background-color: #404040;
        }
        
        QRadioButton::indicator:checked {
            background-color: #61dafb;
            border: 2px solid #61dafb;
        }
        
        QRadioButton::indicator:checked:hover {
            background-color: #4bc5e8;
            border: 2px solid #4bc5e8;
        }
        
        /* Save and Cancel buttons - standard Havoc theme like User Management */
        QPushButton#saveButton, QPushButton#cancelButton {
            background-color: #404040;
            color: #ffffff;
            border: 2px solid #606060;
            border-radius: 8px;
            padding: 12px 20px;
            font-size: 14px;
            font-weight: bold;
            min-width: 120px;
        }
        
        QPushButton#saveButton:hover, QPushButton#cancelButton:hover {
            background-color: #4a4a4a;
            border: 2px solid #61dafb;
        }
        
        QPushButton#saveButton:pressed, QPushButton#cancelButton:pressed {
            background-color: #3a3a3a;
            border: 2px solid #61dafb;
        }
        
        QPushButton#saveButton:disabled, QPushButton#cancelButton:disabled {
            background-color: #2a2a2a;
            color: #666666;
            border: 2px solid #404040;
        }
        
        /* Password visibility button */
        QPushButton#passwordVisibilityButton {
            background-color: #6c757d;
            color: #ffffff;
            border: 2px solid #6c757d;
            border-radius: 6px;
            padding: 8px 12px;
            font-size: 12px;
            font-weight: bold;
            min-width: 40px;
            max-width: 40px;
        }
        
        QPushButton#passwordVisibilityButton:hover {
            background-color: #5a6268;
            border: 2px solid #545b62;
        }
        
        QPushButton#passwordVisibilityButton:pressed {
            background-color: #545b62;
            border: 2px solid #4e555b;
        }
    )");

    // Main layout
    mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    mainLayout->setSpacing(15);

    // Title
    titleLabel = new QLabel(QString("Edit User: %1").arg(originalUsername));
    titleLabel->setObjectName("titleLabel");
    titleLabel->setAlignment(Qt::AlignCenter);

    // Form layout
    formLayout = new QFormLayout();
    formLayout->setSpacing(12);
    formLayout->setLabelAlignment(Qt::AlignLeft);

    // Username field
    usernameEdit = new QLineEdit();
    formLayout->addRow("Username:", usernameEdit);

    // Password field with visibility toggle
    passwordLayout = new QHBoxLayout();
    passwordEdit = new QLineEdit();
    passwordEdit->setEchoMode(QLineEdit::Password);
    passwordEdit->setPlaceholderText("Leave empty to keep current password");
    
    passwordVisibilityButton = new QPushButton("👁");
    passwordVisibilityButton->setObjectName("passwordVisibilityButton");
    passwordVisibilityButton->setToolTip("Toggle password visibility");
    
    passwordLayout->addWidget(passwordEdit);
    passwordLayout->addWidget(passwordVisibilityButton);
    passwordLayout->setContentsMargins(0, 0, 0, 0);
    
    QWidget* passwordWidget = new QWidget();
    passwordWidget->setObjectName("passwordWidget");
    passwordWidget->setLayout(passwordLayout);
    formLayout->addRow("New Password:", passwordWidget);

    // Role field - using radio buttons for cleaner selection
    QLabel* roleLabel = new QLabel("Role:");
    roleLabel->setAlignment(Qt::AlignTop);
    
    roleButtonGroup = new QButtonGroup(this);
    QVBoxLayout* roleLayout = new QVBoxLayout();
    roleLayout->setSpacing(8);
    roleLayout->setContentsMargins(0, 0, 0, 0);
    
    adminRadio = new QRadioButton("admin");
    operatorRadio = new QRadioButton("operator");
    agentOperatorRadio = new QRadioButton("agent-operator");
    
    roleButtonGroup->addButton(adminRadio, 0);
    roleButtonGroup->addButton(operatorRadio, 1);
    roleButtonGroup->addButton(agentOperatorRadio, 2);
    
    roleLayout->addWidget(adminRadio);
    roleLayout->addWidget(operatorRadio);
    roleLayout->addWidget(agentOperatorRadio);
    
    QWidget* roleWidget = new QWidget();
    roleWidget->setObjectName("roleWidget");
    roleWidget->setLayout(roleLayout);
    
    formLayout->addRow(roleLabel, roleWidget);

    // Active field
    activeCheckBox = new QCheckBox("User account is active");
    formLayout->addRow("Status:", activeCheckBox);

    // Button layout
    buttonLayout = new QHBoxLayout();
    
    saveButton = new QPushButton("Save Changes");
    saveButton->setObjectName("saveButton");
    cancelButton = new QPushButton("Cancel");
    cancelButton->setObjectName("cancelButton");
    
    buttonLayout->addStretch();
    buttonLayout->addWidget(saveButton);
    buttonLayout->addWidget(cancelButton);

    // Add layouts to main layout
    mainLayout->addWidget(titleLabel);
    mainLayout->addLayout(formLayout);
    mainLayout->addStretch();
    mainLayout->addLayout(buttonLayout);

    // Connect signals
    connect(saveButton, &QPushButton::clicked, this, &EditUserDialog::onSaveClicked);
    connect(cancelButton, &QPushButton::clicked, this, &EditUserDialog::onCancelClicked);
    connect(passwordVisibilityButton, &QPushButton::clicked, this, &EditUserDialog::onPasswordVisibilityToggled);
}

void EditUserDialog::populateFields()
{
    // Populate form with existing user data
    usernameEdit->setText(originalUserData["username"].toString());
    
    // Set role
    QString currentRole = originalUserData["role"].toString();
    if (currentRole == "admin") {
        adminRadio->setChecked(true);
    } else if (currentRole == "operator") {
        operatorRadio->setChecked(true);
    } else if (currentRole == "agent-operator") {
        agentOperatorRadio->setChecked(true);
    } else {
        adminRadio->setChecked(true); // Default to admin
    }
    
    // Set active status
    bool isActive = originalUserData["active"].toBool();
    activeCheckBox->setChecked(isActive);
    
    // Password field starts empty (placeholder shows instructions)
}

void EditUserDialog::onSaveClicked()
{
    if (!validateInputs()) {
        return;
    }
    
    // Disable save button during request
    saveButton->setEnabled(false);
    saveButton->setText("Saving...");
    
    makeUpdateRequest();
}

void EditUserDialog::onCancelClicked()
{
    // Cancel any pending request
    if (currentReply != nullptr) {
        currentReply->abort();
        currentReply->deleteLater();
        currentReply = nullptr;
    }
    
    reject();
}

void EditUserDialog::onPasswordVisibilityToggled()
{
    if (passwordEdit->echoMode() == QLineEdit::Password) {
        passwordEdit->setEchoMode(QLineEdit::Normal);
        passwordVisibilityButton->setText("🙈");
    } else {
        passwordEdit->setEchoMode(QLineEdit::Password);
        passwordVisibilityButton->setText("👁");
    }
}

bool EditUserDialog::validateInputs()
{
    // Validate username
    QString newUsername = usernameEdit->text().trimmed();
    if (newUsername.isEmpty()) {
        showErrorMessage("Validation Error", "Username cannot be empty.");
        usernameEdit->setFocus();
        return false;
    }
    
    // Validate username length and characters
    if (newUsername.length() < 3) {
        showErrorMessage("Validation Error", "Username must be at least 3 characters long.");
        usernameEdit->setFocus();
        return false;
    }
    
    if (newUsername.length() > 50) {
        showErrorMessage("Validation Error", "Username cannot exceed 50 characters.");
        usernameEdit->setFocus();
        return false;
    }
    
    // Check for valid username characters (alphanumeric, underscore, hyphen)
    QRegExp usernameRegex("^[a-zA-Z0-9_-]+$");
    if (!usernameRegex.exactMatch(newUsername)) {
        showErrorMessage("Validation Error", "Username can only contain letters, numbers, underscores, and hyphens.");
        usernameEdit->setFocus();
        return false;
    }
    
    // Validate password (if provided)
    QString newPassword = passwordEdit->text();
    if (!newPassword.isEmpty()) {
        if (newPassword.length() < 8) {
            showErrorMessage("Validation Error", "Password must be at least 8 characters long.");
            passwordEdit->setFocus();
            return false;
        }
        
        if (newPassword.length() > 128) {
            showErrorMessage("Validation Error", "Password cannot exceed 128 characters.");
            passwordEdit->setFocus();
            return false;
        }
    }
    
    return true;
}

void EditUserDialog::makeUpdateRequest()
{
    // Cancel any existing request
    if (currentReply != nullptr) {
        currentReply->abort();
        currentReply->deleteLater();
        currentReply = nullptr;
    }
    
    // Get connection info from global teamserver connection
    QString baseUrl = QString("https://%1:%2").arg(HavocX::Teamserver.Host).arg(HavocX::Teamserver.Port);
    QUrl url(baseUrl + "/auth/users/update");
    
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    
    // Set aggressive timeouts for C2 operations - fail fast rather than wait
    request.setTransferTimeout(5000); // 5 second timeout instead of default 30+
    request.setAttribute(QNetworkRequest::HttpPipeliningAllowedAttribute, true);
    
    // Add authentication header
    if (!authToken.isEmpty()) {
        request.setRawHeader("Authorization", QString("Bearer %1").arg(authToken).toUtf8());
    }
    
    // Build update data
    QJsonObject updateData;
    updateData["original_username"] = originalUsername;
    updateData["username"] = usernameEdit->text().trimmed();
    
    // Get selected role from radio buttons
    QString selectedRole = "admin"; // Default
    if (adminRadio->isChecked()) {
        selectedRole = "admin";
    } else if (operatorRadio->isChecked()) {
        selectedRole = "operator";
    } else if (agentOperatorRadio->isChecked()) {
        selectedRole = "agent-operator";
    }
    updateData["role"] = selectedRole;
    updateData["active"] = activeCheckBox->isChecked();
    
    // Include password only if changed
    QString newPassword = passwordEdit->text();
    if (!newPassword.isEmpty()) {
        // Hash the password with SHA3-256 (matching the auth system)
        QString hashedPassword = QString(QCryptographicHash::hash(newPassword.toLocal8Bit(), QCryptographicHash::Sha3_256).toHex());
        updateData["password"] = hashedPassword;
    }
    
    QJsonDocument doc(updateData);
    
    try {
        currentReply = networkManager->post(request, doc.toJson());
    } catch (const std::exception& e) {
        showErrorMessage("Network Error", QString("Failed to make update request: %1").arg(e.what()));
        // Re-enable save button
        saveButton->setEnabled(true);
        saveButton->setText("Save Changes");
    } catch (...) {
        showErrorMessage("Network Error", "Unknown error occurred while making update request");
        // Re-enable save button
        saveButton->setEnabled(true);
        saveButton->setText("Save Changes");
    }
}

void EditUserDialog::onNetworkReplyFinished()
{
    if (currentReply == nullptr) {
        return;
    }
    
    try {
        QNetworkReply::NetworkError error = currentReply->error();
        QString errorString = currentReply->errorString(); // Get error string before deletion
        QByteArray responseData = currentReply->readAll();
        
        currentReply->deleteLater();
        currentReply = nullptr;
        
        // Re-enable save button
        saveButton->setEnabled(true);
        saveButton->setText("Save Changes");
        
        if (error != QNetworkReply::NoError) {
            QString errorMsg = QString("Network error: %1").arg(errorString);
            showErrorMessage("Update Failed", errorMsg);
            return;
        }
        
        // Parse response
        QJsonDocument doc = QJsonDocument::fromJson(responseData);
        QJsonObject obj = doc.object();
        
        if (obj.contains("success") && obj["success"].toBool()) {
            // Close dialog immediately on success - no unnecessary delays for C2 operations
            accept();
        } else {
            QString errorMsg = "Update failed";
            if (obj.contains("message")) {
                errorMsg = obj["message"].toString();
            }
            showErrorMessage("Update Failed", errorMsg);
        }
        
    } catch (const std::exception& e) {
        // Re-enable save button
        saveButton->setEnabled(true);
        saveButton->setText("Save Changes");
        showErrorMessage("Response Error", QString("Error processing server response: %1").arg(e.what()));
    } catch (...) {
        // Re-enable save button
        saveButton->setEnabled(true);
        saveButton->setText("Save Changes");
        showErrorMessage("Response Error", "Unknown error processing server response");
    }
}

void EditUserDialog::showErrorMessage(const QString& title, const QString& message)
{
    QMessageBox msgBox(this);
    msgBox.setWindowTitle(title);
    msgBox.setText(message);
    msgBox.setIcon(QMessageBox::Critical);
    msgBox.setStyleSheet(
        "QMessageBox {"
        "    background-color: #2b2b2b;"
        "    color: #ffffff;"
        "}"
        "QMessageBox QPushButton {"
        "    background-color: #404040;"
        "    color: #ffffff;"
        "    border: 1px solid #606060;"
        "    border-radius: 4px;"
        "    padding: 6px 12px;"
        "    min-width: 60px;"
        "}"
        "QMessageBox QPushButton:hover {"
        "    background-color: #4a4a4a;"
        "    border: 1px solid #61dafb;"
        "}"
    );
    msgBox.exec();
}

void EditUserDialog::showSuccessMessage(const QString& message)
{
    QMessageBox msgBox(this);
    msgBox.setWindowTitle("Success");
    msgBox.setText(message);
    msgBox.setIcon(QMessageBox::Information);
    msgBox.setStyleSheet(
        "QMessageBox {"
        "    background-color: #2b2b2b;"
        "    color: #ffffff;"
        "}"
        "QMessageBox QPushButton {"
        "    background-color: #1e7e34;"
        "    color: #ffffff;"
        "    border: 1px solid #155724;"
        "    border-radius: 4px;"
        "    padding: 6px 12px;"
        "    min-width: 60px;"
        "}"
        "QMessageBox QPushButton:hover {"
        "    background-color: #28a745;"
        "    border: 1px solid #61dafb;"
        "}"
    );
    msgBox.exec();
}
