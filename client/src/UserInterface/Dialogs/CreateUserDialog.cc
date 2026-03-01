#include <UserInterface/Dialogs/CreateUserDialog.hpp>
#include <QCryptographicHash>
#include <QTimer>

CreateUserDialog::CreateUserDialog(const QString& sessionToken, QWidget* parent)
    : QDialog(parent), authToken(sessionToken)
{
    networkManager = new QNetworkAccessManager(this);
    currentReply = nullptr;
    
    setupUi();
    
    // Connect network manager using lambda to avoid MOC complications
    connect(networkManager, &QNetworkAccessManager::finished, [this]() { onNetworkReplyFinished(); });
}

void CreateUserDialog::setupUi()
{
    setWindowTitle("Create User");
    setModal(true);
    setFixedSize(500, 480);
    setObjectName("CreateUserDialog");
    
    // Apply modern Havoc dark theme styling consistent with EditUserDialog
    setStyleSheet(R"(
        QDialog#CreateUserDialog {
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
        
        QWidget#roleWidget {
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
        
        /* Radio button styling */
        QRadioButton {
            color: #ffffff;
            font-size: 14px;
            spacing: 8px;
            margin: 6px 0;
        }
        
        QRadioButton::indicator {
            width: 18px;
            height: 18px;
            border-radius: 9px;
            border: 2px solid #555555;
            background-color: #383838;
        }
        
        QRadioButton::indicator:hover {
            border: 2px solid #61dafb;
            background-color: #404040;
        }
        
        QRadioButton::indicator:checked {
            border: 2px solid #61dafb;
            background-color: #61dafb;
        }
        
        QRadioButton::indicator:checked:hover {
            border: 2px solid #4fa8c5;
            background-color: #4fa8c5;
        }
        
        /* Checkbox styling */
        QCheckBox {
            color: #ffffff;
            font-size: 14px;
            spacing: 8px;
        }
        
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
            border-radius: 4px;
            border: 2px solid #555555;
            background-color: #383838;
        }
        
        QCheckBox::indicator:hover {
            border: 2px solid #61dafb;
            background-color: #404040;
        }
        
        QCheckBox::indicator:checked {
            border: 2px solid #61dafb;
            background-color: #61dafb;
            image: url(data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAiIGhlaWdodD0iMTAiIHZpZXdCb3g9IjAgMCAxMCAxMCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTEuNSA1TDQgNy41TDguNSAyLjUiIHN0cm9rZT0iIzAwMCIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz4KPC9zdmc+);
        }
        
        QCheckBox::indicator:checked:hover {
            border: 2px solid #4fa8c5;
            background-color: #4fa8c5;
        }
        
        /* Password visibility button styling */
        QPushButton#passwordVisibilityButton {
            background-color: #404040;
            color: #ffffff;
            border: 2px solid #555555;
            border-radius: 6px;
            padding: 8px;
            font-size: 16px;
            min-width: 40px;
            max-width: 40px;
            margin-left: 5px;
        }
        
        QPushButton#passwordVisibilityButton:hover {
            background-color: #4a4a4a;
            border: 2px solid #61dafb;
        }
        
        QPushButton#passwordVisibilityButton:pressed {
            background-color: #363636;
        }
        
        /* Create and Cancel buttons - consistent styling */
        QPushButton#createButton {
            background-color: #404040;
            color: #ffffff;
            border: 2px solid #606060;
            border-radius: 8px;
            padding: 12px 20px;
            font-size: 14px;
            font-weight: bold;
            min-width: 120px;
        }
        
        QPushButton#createButton:hover {
            background-color: #4a4a4a;
            border: 2px solid #61dafb;
        }
        
        QPushButton#createButton:pressed {
            background-color: #363636;
        }
        
        QPushButton#createButton:disabled {
            background-color: #2a2a2a;
            color: #777777;
            border: 2px solid #404040;
        }
        
        QPushButton#cancelButton {
            background-color: #404040;
            color: #ffffff;
            border: 2px solid #606060;
            border-radius: 8px;
            padding: 12px 20px;
            font-size: 14px;
            font-weight: bold;
            min-width: 120px;
        }
        
        QPushButton#cancelButton:hover {
            background-color: #4a4a4a;
            border: 2px solid #61dafb;
        }
        
        QPushButton#cancelButton:pressed {
            background-color: #363636;
        }
    )");

    // Main layout
    mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(25, 25, 25, 25);
    mainLayout->setSpacing(20);

    // Title
    titleLabel = new QLabel("Create New User");
    titleLabel->setObjectName("titleLabel");
    titleLabel->setAlignment(Qt::AlignCenter);

    // Form layout
    formLayout = new QFormLayout();
    formLayout->setSpacing(20);
    formLayout->setLabelAlignment(Qt::AlignLeft);

    // Username field
    usernameEdit = new QLineEdit();
    usernameEdit->setPlaceholderText("Enter username (3-50 characters)");
    formLayout->addRow("Username:", usernameEdit);

    // Password field with visibility toggle
    passwordLayout = new QHBoxLayout();
    passwordEdit = new QLineEdit();
    passwordEdit->setEchoMode(QLineEdit::Password);
    passwordEdit->setPlaceholderText("Enter password (8+ characters)");
    
    passwordVisibilityButton = new QPushButton("👁");
    passwordVisibilityButton->setObjectName("passwordVisibilityButton");
    passwordVisibilityButton->setToolTip("Toggle password visibility");
    
    passwordLayout->addWidget(passwordEdit);
    passwordLayout->addWidget(passwordVisibilityButton);
    passwordLayout->setContentsMargins(0, 0, 0, 0);
    
    QWidget* passwordWidget = new QWidget();
    passwordWidget->setObjectName("passwordWidget");
    passwordWidget->setLayout(passwordLayout);
    
    formLayout->addRow("Password:", passwordWidget);

    // Role selection with radio buttons
    QLabel* roleLabel = new QLabel("Role:");
    roleLayout = new QVBoxLayout();
    roleLayout->setSpacing(8);
    
    roleButtonGroup = new QButtonGroup(this);
    adminRadio = new QRadioButton("admin");
    operatorRadio = new QRadioButton("operator");
    agentOperatorRadio = new QRadioButton("agent-operator");
    
    // Default to operator role
    operatorRadio->setChecked(true);
    
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
    activeCheckBox->setChecked(true); // Default to active
    formLayout->addRow("Status:", activeCheckBox);

    // Button layout
    buttonLayout = new QHBoxLayout();
    
    createButton = new QPushButton("Create User");
    createButton->setObjectName("createButton");
    cancelButton = new QPushButton("Cancel");
    cancelButton->setObjectName("cancelButton");
    
    buttonLayout->addStretch();
    buttonLayout->addWidget(createButton);
    buttonLayout->addWidget(cancelButton);

    // Add layouts to main layout
    mainLayout->addWidget(titleLabel);
    mainLayout->addLayout(formLayout);
    mainLayout->addStretch();
    mainLayout->addLayout(buttonLayout);

    // Connect signals using lambdas to avoid MOC complications
    connect(createButton, &QPushButton::clicked, [this]() { onCreateClicked(); });
    connect(cancelButton, &QPushButton::clicked, [this]() { onCancelClicked(); });
    connect(passwordVisibilityButton, &QPushButton::clicked, [this]() { onPasswordVisibilityToggled(); });
    
    // Set focus to username field
    usernameEdit->setFocus();
}

void CreateUserDialog::onCreateClicked()
{
    if (!validateInputs()) {
        return;
    }
    
    // Disable create button during request
    createButton->setEnabled(false);
    createButton->setText("Creating...");
    
    makeCreateRequest();
}

void CreateUserDialog::onCancelClicked()
{
    // Cancel any pending request
    if (currentReply != nullptr) {
        currentReply->abort();
        currentReply->deleteLater();
        currentReply = nullptr;
    }
    
    reject();
}

void CreateUserDialog::onPasswordVisibilityToggled()
{
    if (passwordEdit->echoMode() == QLineEdit::Password) {
        passwordEdit->setEchoMode(QLineEdit::Normal);
        passwordVisibilityButton->setText("🙈");
    } else {
        passwordEdit->setEchoMode(QLineEdit::Password);
        passwordVisibilityButton->setText("👁");
    }
}

bool CreateUserDialog::validateInputs()
{
    // Validate username
    QString username = usernameEdit->text().trimmed();
    if (username.isEmpty()) {
        showErrorMessage("Validation Error", "Username cannot be empty.");
        usernameEdit->setFocus();
        return false;
    }
    
    // Validate username length and characters
    if (username.length() < 3) {
        showErrorMessage("Validation Error", "Username must be at least 3 characters long.");
        usernameEdit->setFocus();
        return false;
    }
    
    if (username.length() > 50) {
        showErrorMessage("Validation Error", "Username cannot exceed 50 characters.");
        usernameEdit->setFocus();
        return false;
    }
    
    // Check for valid username characters (alphanumeric, underscore, hyphen)
    QRegExp usernameRegex("^[a-zA-Z0-9_-]+$");
    if (!usernameRegex.exactMatch(username)) {
        showErrorMessage("Validation Error", "Username can only contain letters, numbers, underscores, and hyphens.");
        usernameEdit->setFocus();
        return false;
    }
    
    // Validate password
    QString password = passwordEdit->text();
    if (password.isEmpty()) {
        showErrorMessage("Validation Error", "Password cannot be empty.");
        passwordEdit->setFocus();
        return false;
    }
    
    if (password.length() < 8) {
        showErrorMessage("Validation Error", "Password must be at least 8 characters long.");
        passwordEdit->setFocus();
        return false;
    }
    
    if (password.length() > 128) {
        showErrorMessage("Validation Error", "Password cannot exceed 128 characters.");
        passwordEdit->setFocus();
        return false;
    }
    
    return true;
}

void CreateUserDialog::makeCreateRequest()
{
    // Cancel any existing request
    if (currentReply != nullptr) {
        currentReply->abort();
        currentReply->deleteLater();
        currentReply = nullptr;
    }
    
    // Get connection info from global teamserver connection
    QString baseUrl = QString("https://%1:%2").arg(HavocX::Teamserver.Host).arg(HavocX::Teamserver.Port);
    QUrl url(baseUrl + "/auth/users/create");
    
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    
    // Set aggressive timeouts for C2 operations - fail fast rather than wait
    request.setTransferTimeout(5000); // 5 second timeout instead of default 30+
    request.setAttribute(QNetworkRequest::HttpPipeliningAllowedAttribute, true);
    
    // Add authentication header
    if (!authToken.isEmpty()) {
        request.setRawHeader("Authorization", QString("Bearer %1").arg(authToken).toUtf8());
    }
    
    // Build create data
    QJsonObject createData;
    createData["username"] = usernameEdit->text().trimmed();
    
    // Get selected role from radio buttons
    QString selectedRole = "operator"; // Default
    if (adminRadio->isChecked()) {
        selectedRole = "admin";
    } else if (operatorRadio->isChecked()) {
        selectedRole = "operator";
    } else if (agentOperatorRadio->isChecked()) {
        selectedRole = "agent-operator";
    }
    createData["role"] = selectedRole;
    createData["active"] = activeCheckBox->isChecked();
    
    // Hash the password with SHA3-256 (matching the auth system)
    QString password = passwordEdit->text();
    QString hashedPassword = QString(QCryptographicHash::hash(password.toLocal8Bit(), QCryptographicHash::Sha3_256).toHex());
    createData["password"] = hashedPassword;
    
    QJsonDocument doc(createData);
    
    try {
        currentReply = networkManager->post(request, doc.toJson());
    } catch (const std::exception& e) {
        showErrorMessage("Network Error", QString("Failed to make create request: %1").arg(e.what()));
        // Re-enable create button
        createButton->setEnabled(true);
        createButton->setText("Create User");
    } catch (...) {
        showErrorMessage("Network Error", "Unknown error occurred while making create request");
        // Re-enable create button
        createButton->setEnabled(true);
        createButton->setText("Create User");
    }
}

void CreateUserDialog::onNetworkReplyFinished()
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
        
        // Re-enable create button
        createButton->setEnabled(true);
        createButton->setText("Create User");
        
        if (error != QNetworkReply::NoError) {
            QString errorMsg = QString("Network error: %1").arg(errorString);
            showErrorMessage("Create Failed", errorMsg);
            return;
        }
        
        // Parse response
        QJsonDocument doc = QJsonDocument::fromJson(responseData);
        QJsonObject obj = doc.object();
        
        if (obj.contains("success") && obj["success"].toBool()) {
            // Close dialog immediately on success - no unnecessary delays for C2 operations
            accept();
        } else {
            QString errorMsg = "User creation failed";
            if (obj.contains("message")) {
                errorMsg = obj["message"].toString();
            }
            showErrorMessage("Create Failed", errorMsg);
        }
        
    } catch (const std::exception& e) {
        // Re-enable create button
        createButton->setEnabled(true);
        createButton->setText("Create User");
        showErrorMessage("Response Error", QString("Error processing server response: %1").arg(e.what()));
    } catch (...) {
        // Re-enable create button
        createButton->setEnabled(true);
        createButton->setText("Create User");
        showErrorMessage("Response Error", "Unknown error processing server response");
    }
}

void CreateUserDialog::showErrorMessage(const QString& title, const QString& message)
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

void CreateUserDialog::showSuccessMessage(const QString& message)
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
