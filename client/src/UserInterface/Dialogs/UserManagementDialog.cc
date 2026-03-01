#include <UserInterface/Dialogs/UserManagementDialog.hpp>
#include <UserInterface/Dialogs/EditUserDialog.hpp>
#include <UserInterface/Dialogs/CreateUserDialog.hpp>
#include <UserInterface/Dialogs/AgentAssignmentDialog.hpp>
#include <QtNetwork/QNetworkRequest>
#include <QHeaderView>
#include <QMessageBox>
#include <QJsonParseError>
#include <QTimer>
#include <QCryptographicHash>
#include <global.hpp>

UserManagementDialog::UserManagementDialog(QWidget *parent)
    : QDialog(parent), networkManager(new QNetworkAccessManager(this)), currentReply(nullptr)
{
    // Initialize UI first
    setupUi();
    
    // Validate critical UI components were created successfully
    if (!userTable || !statusLabel || !networkManager) {
        throw std::runtime_error("Failed to initialize critical UI components");
    }
    
    // Configure SSL for self-signed certificates (like the teamserver)
    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone);
    QSslConfiguration::setDefaultConfiguration(sslConfig);
    
    // Connect the finished signal to our slot for handling responses
    connect(networkManager, &QNetworkAccessManager::finished, [this](QNetworkReply* reply) {
        if (reply) {
            this->currentReply = reply; // Set current reply for the handler
            this->onNetworkReplyFinished();
        }
    });
    
    // Connect SSL error handler to ignore certificate errors (like WebSocket does)
    connect(networkManager, &QNetworkAccessManager::sslErrors, [](QNetworkReply* reply, const QList<QSslError>& errors) {
        reply->ignoreSslErrors(errors);
    });
    
    // Load initial data with a small delay to ensure UI is fully initialized
    QTimer::singleShot(100, [this]() {
        refreshUserList();
    });
}

void UserManagementDialog::setupUi()
{
    setObjectName("UserManagementDialog");
    setWindowTitle("User Management");
    setFixedSize(800, 600);
    
    // Apply Havoc's dark theme styling (identical to AdminFeatureDialog)
    setStyleSheet(R"(
        QDialog#UserManagementDialog {
            background-color: #2b2b2b;
            color: #ffffff;
            border: 2px solid #404040;
            border-radius: 8px;
        }
        
        QLabel {
            color: #ffffff;
            background-color: transparent;
            border: none;
        }
        
        QLabel#statusLabel {
            font-size: 12px;
            color: #cccccc;
            margin: 5px 0;
        }
        
        QPushButton {
            background-color: #404040;
            color: #ffffff;
            border: 1px solid #606060;
            border-radius: 6px;
            padding: 8px 16px;
            font-size: 13px;
            font-weight: bold;
            min-width: 120px;
        }
        
        QPushButton:hover {
            background-color: #4a4a4a;
            border: 1px solid #61dafb;
        }
        
        QPushButton:pressed {
            background-color: #3a3a3a;
            border: 1px solid #61dafb;
        }
        
        QPushButton:focus {
            outline: none;
            border: 1px solid #61dafb;
        }
        
        QPushButton:disabled {
            background-color: #2a2a2a;
            color: #666666;
            border: 1px solid #404040;
        }
        
        QTableWidget {
            background-color: #333333;
            color: #ffffff;
            border: 1px solid #606060;
            border-radius: 6px;
            gridline-color: #505050;
            selection-background-color: #61dafb;
            selection-color: #000000;
            outline: none;
        }
        
        QTableWidget:focus {
            outline: none;
            border: 1px solid #606060;
        }
        
        QTableWidget::item {
            padding: 8px;
            border-bottom: 1px solid #505050;
            outline: none;
        }
        
        QTableWidget::item:selected {
            background-color: #61dafb;
            color: #000000;
            outline: none;
        }
        
        QTableWidget::item:focus {
            outline: none;
            border: none;
        }
        
        /* Horizontal header styling */
        QTableWidget QHeaderView::section:horizontal {
            background-color: #404040;
            color: #ffffff;
            border: 1px solid #606060;
            padding: 8px;
            font-weight: bold;
        }
        
        QTableWidget QHeaderView::section:horizontal:hover {
            background-color: #4a4a4a;
        }
        
        /* Vertical header (row numbers) styling - more specific targeting */
        QTableWidget QHeaderView::section:vertical {
            background-color: #333333;
            color: #cccccc;
            border: 1px solid #505050;
            padding: 4px;
            font-weight: normal;
            font-size: 12px;
            min-width: 30px;
        }
        
        QTableWidget QHeaderView::section:vertical:hover {
            background-color: #3a3a3a;
        }
        
        /* Alternative targeting for vertical header */
        QTableWidget::verticalHeader {
            background-color: #333333;
            color: #cccccc;
            border: none;
        }
        
        QTableWidget::verticalHeader::section {
            background-color: #333333;
            color: #cccccc;
            border: 1px solid #505050;
            padding: 4px;
            font-weight: normal;
        }
    )");

    // Main layout
    mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    mainLayout->setSpacing(15);

    // Header layout - just status info, window title already shows "User Management"
    headerLayout = new QHBoxLayout();
    
    statusLabel = new QLabel("Loading users...");
    statusLabel->setObjectName("statusLabel");
    statusLabel->setAlignment(Qt::AlignRight);
    
    headerLayout->addStretch();
    headerLayout->addWidget(statusLabel);

    // User table
    userTable = new QTableWidget(0, 5);
    QStringList headers = {"Username", "Role", "Active", "Last Login", "Created By"};
    userTable->setHorizontalHeaderLabels(headers);
    userTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    userTable->setSelectionMode(QAbstractItemView::SingleSelection);
    userTable->setAlternatingRowColors(true);
    userTable->setSortingEnabled(true);
    
    // Set column widths
    userTable->setColumnWidth(0, 150); // Username
    userTable->setColumnWidth(1, 120); // Role
    userTable->setColumnWidth(2, 80);  // Active
    userTable->setColumnWidth(3, 150); // Last Login
    userTable->setColumnWidth(4, 120); // Created By
    
    // Stretch last column
    userTable->horizontalHeader()->setStretchLastSection(true);
    
    // Force vertical header styling with multiple approaches
    QHeaderView* verticalHeader = userTable->verticalHeader();
    if (verticalHeader) {
        // Option 1: Hide the vertical header completely (cleanest solution)
        verticalHeader->setVisible(false);
        
        // Alternative Option 2: Force palette colors (uncomment if you want row numbers)
        /*
        QPalette palette = verticalHeader->palette();
        palette.setColor(QPalette::Background, QColor(51, 51, 51));      // #333333
        palette.setColor(QPalette::Base, QColor(51, 51, 51));           // #333333  
        palette.setColor(QPalette::Window, QColor(51, 51, 51));         // #333333
        palette.setColor(QPalette::Button, QColor(51, 51, 51));         // #333333
        palette.setColor(QPalette::WindowText, QColor(204, 204, 204));  // #cccccc
        palette.setColor(QPalette::ButtonText, QColor(204, 204, 204));  // #cccccc
        verticalHeader->setPalette(palette);
        verticalHeader->setAutoFillBackground(true);
        
        verticalHeader->setStyleSheet(
            "QHeaderView::section {"
            "    background-color: #333333 !important;"
            "    color: #cccccc !important;"
            "    border: 1px solid #505050;"
            "    padding: 4px;"
            "    font-weight: normal;"
            "    font-size: 12px;"
            "}"
            "QHeaderView::section:hover {"
            "    background-color: #3a3a3a !important;"
            "}"
            "QHeaderView {"
            "    background-color: #333333 !important;"
            "    color: #cccccc !important;"
            "}"
        );
        verticalHeader->setDefaultSectionSize(25);
        verticalHeader->setMinimumSectionSize(20);
        */
    }

    // Button layouts - Split into two rows for better organization
    actionButtonLayout = new QHBoxLayout();
    utilityButtonLayout = new QHBoxLayout();
    
    createUserButton = new QPushButton("Create User");
    editUserButton = new QPushButton("Edit User");
    deleteUserButton = new QPushButton("Delete User");
    assignAgentsButton = new QPushButton("Assign Agents");
    refreshButton = new QPushButton("Refresh");
    closeButton = new QPushButton("Close");
    
    // Initially disable action buttons until user selection
    editUserButton->setEnabled(false);
    deleteUserButton->setEnabled(false);
    assignAgentsButton->setEnabled(false);
    
    // Action buttons (top row) - User management operations
    actionButtonLayout->addWidget(createUserButton);
    actionButtonLayout->addWidget(editUserButton);
    actionButtonLayout->addWidget(deleteUserButton);
    actionButtonLayout->addWidget(assignAgentsButton);
    actionButtonLayout->addStretch(); // Push buttons to the left
    
    // Utility buttons (bottom row) - General operations
    utilityButtonLayout->addStretch(); // Push buttons to the right
    utilityButtonLayout->addWidget(refreshButton);
    utilityButtonLayout->addWidget(closeButton);

    // Add layouts to main layout
    mainLayout->addLayout(headerLayout);
    mainLayout->addWidget(userTable);
    mainLayout->addLayout(actionButtonLayout);
    mainLayout->addLayout(utilityButtonLayout);

    // Connect signals
    connect(createUserButton, &QPushButton::clicked, [this]() { onCreateUserClicked(); });
    connect(editUserButton, &QPushButton::clicked, [this]() { onEditUserClicked(); });
    connect(deleteUserButton, &QPushButton::clicked, [this]() { onDeleteUserClicked(); });
    connect(assignAgentsButton, &QPushButton::clicked, [this]() { onAssignAgentsClicked(); });
    connect(refreshButton, &QPushButton::clicked, [this]() { onRefreshClicked(); });
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    
    connect(userTable, &QTableWidget::itemSelectionChanged, [this]() { onUserSelectionChanged(); });
    
    // Handle Escape key
    connect(this, &QDialog::rejected, this, &QDialog::close);
}

void UserManagementDialog::refreshUserList()
{
    statusLabel->setText("Authenticating...");
    
    // First, get a session token using WebSocket credentials
    authenticateForHttpSession();
}

void UserManagementDialog::authenticateForHttpSession()
{
    // Cancel any existing request
    if (currentReply != nullptr) {
        currentReply->abort();
        currentReply->deleteLater();
        currentReply = nullptr;
    }
    
    // Get connection info from the active teamserver connection  
    QString baseUrl = QString("https://%1:%2").arg(HavocX::Teamserver.Host).arg(HavocX::Teamserver.Port);
    QUrl url(baseUrl + "/auth/websocket-session");
    
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    
    // Create JSON payload with WebSocket credentials (SHA3-256 hashed like WebSocket does)
    QJsonObject authData;
    authData["username"] = HavocX::Teamserver.User;
    authData["password"] = QString(QCryptographicHash::hash(HavocX::Teamserver.Password.toLocal8Bit(), QCryptographicHash::Sha3_256).toHex());
    
    QJsonDocument doc(authData);
    currentRequestType = "auth";
    currentReply = networkManager->post(request, doc.toJson());
}

void UserManagementDialog::handleAuthResponse(const QJsonDocument& doc)
{
    QJsonObject obj = doc.object();
    
    if (obj.contains("success") && obj["success"].toBool()) {
        // Authentication successful, extract session token
        if (obj.contains("session_id")) {
            sessionToken = obj["session_id"].toString();
            statusLabel->setText("Authenticated, loading users...");
            
            // Now make the actual API request with the session token
            makeApiRequest("/auth/users", "GET");
        } else {
            statusLabel->setText("Authentication response error");
            showErrorMessage("Authentication Error", "No session token received");
        }
    } else {
        statusLabel->setText("Authentication failed");
        QString errorMsg = "Authentication failed";
        if (obj.contains("message")) {
            errorMsg = obj["message"].toString();
        }
        showErrorMessage("Authentication Error", errorMsg);
    }
}

void UserManagementDialog::makeApiRequest(const QString& endpoint, const QString& method, const QJsonObject& data)
{
    // Cancel any existing request
    if (currentReply != nullptr) {
        currentReply->abort();
        currentReply->deleteLater();
        currentReply = nullptr;
    }
    
    // Get connection info from the active teamserver connection  
    QString baseUrl = QString("https://%1:%2").arg(HavocX::Teamserver.Host).arg(HavocX::Teamserver.Port);
    QUrl url(baseUrl + endpoint);
    
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    
    // Add authentication header if we have a session token
    if (!sessionToken.isEmpty()) {
        request.setRawHeader("Authorization", QString("Bearer %1").arg(sessionToken).toUtf8());
    }
    
    // Set request type based on endpoint for proper response handling
    if (endpoint.contains("/delete")) {
        currentRequestType = "delete";
    } else {
        currentRequestType = "users";
    }
    
    try {
        if (method == "GET") {
            currentReply = networkManager->get(request);
        } else if (method == "POST") {
            QJsonDocument doc(data);
            currentReply = networkManager->post(request, doc.toJson());
        } else if (method == "DELETE") {
            QJsonDocument doc(data);
            currentReply = networkManager->sendCustomRequest(request, "DELETE", doc.toJson());
        }
    } catch (const std::exception& e) {
        showErrorMessage("Network Error", QString("Failed to make request: %1").arg(e.what()));
    } catch (...) {
        showErrorMessage("Network Error", "Unknown error occurred while making request");
    }
}

void UserManagementDialog::onNetworkReplyFinished()
{
    if (currentReply == nullptr) {
        return;
    }
    
    try {
        QNetworkReply::NetworkError error = currentReply->error();
        int statusCode = currentReply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        QByteArray responseData = currentReply->readAll();
        QString errorString = currentReply->errorString(); // Get error string before deleting
        QString requestType = currentRequestType; // Store before cleaning up
        
        currentReply->deleteLater();
        currentReply = nullptr;
        currentRequestType.clear();
        
        if (error != QNetworkReply::NoError) {
            statusLabel->setText("Network error");
            showErrorMessage("Network Error", QString("Request failed: %1").arg(errorString));
            return;
        }
        
        if (statusCode == 401) {
            statusLabel->setText("Authentication required");
            showErrorMessage("Authentication Error", "Admin authentication required. Please login as an administrator.");
            return;
        }
        
        if (statusCode == 403) {
            statusLabel->setText("Access denied");
            showErrorMessage("Access Denied", "Admin privileges required for user management.");
            return;
        }
        
        if (statusCode != 200) {
            statusLabel->setText("Request failed");
            showErrorMessage("Error", QString("Server returned status code: %1").arg(statusCode));
            return;
        }
        
        // Parse JSON response
        QJsonParseError parseError;
        QJsonDocument doc = QJsonDocument::fromJson(responseData, &parseError);
        if (parseError.error != QJsonParseError::NoError) {
            statusLabel->setText("Parse error");
            showErrorMessage("Parse Error", QString("Failed to parse response: %1").arg(parseError.errorString()));
            return;
        }
        
        // Handle different response types
        if (requestType == "auth") {
            handleAuthResponse(doc);
        } else if (requestType == "users") {
            handleUserListResponse(doc);
        } else if (requestType == "delete") {
            handleDeleteResponse(doc);
        } else {
            statusLabel->setText("Unknown response");
            showErrorMessage("Error", "Received unexpected response type");
        }
        
    } catch (const std::exception& e) {
        statusLabel->setText("Exception occurred");
        showErrorMessage("Exception", QString("Error processing response: %1").arg(e.what()));
    } catch (...) {
        statusLabel->setText("Unknown error");
        showErrorMessage("Error", "Unknown error occurred while processing response");
    }
}

void UserManagementDialog::handleUserListResponse(const QJsonDocument& doc)
{
    try {
        QJsonObject obj = doc.object();
        
        if (obj.contains("users") && obj["users"].isArray()) {
            userData = obj["users"].toArray();
            
            // Disable sorting during population to prevent row/data mismatch
            userTable->setSortingEnabled(false);
            
            // Clear existing data
            userTable->setRowCount(0);
            
            // Populate table with comprehensive validation
            for (int i = 0; i < userData.size(); ++i) {
                QJsonObject user = userData[i].toObject();
                
                userTable->insertRow(i);
                
                // Safely extract user data with fallbacks for missing fields
                QString username = user.contains("username") ? user["username"].toString() : "Unknown";
                QString role = user.contains("role") ? user["role"].toString() : "Unknown";
                QString active = user.contains("active") ? (user["active"].toBool() ? "Yes" : "No") : "Unknown";
                QString lastLogin = user.contains("last_login") ? user["last_login"].toString() : "Never";
                QString createdBy = user.contains("created_by") ? user["created_by"].toString() : "Unknown";
                
                // Create table items with null checks
                try {
                    QTableWidgetItem* usernameItem = new QTableWidgetItem(username.isEmpty() ? "Unknown" : username);
                    QTableWidgetItem* roleItem = new QTableWidgetItem(role.isEmpty() ? "Unknown" : role);
                    QTableWidgetItem* activeItem = new QTableWidgetItem(active.isEmpty() ? "Unknown" : active);
                    QTableWidgetItem* lastLoginItem = new QTableWidgetItem(lastLogin.isEmpty() ? "Never" : lastLogin);
                    QTableWidgetItem* createdByItem = new QTableWidgetItem(createdBy.isEmpty() ? "Unknown" : createdBy);
                    
                    // Store the original user data index in each item for sorting safety
                    usernameItem->setData(Qt::UserRole, i);
                    roleItem->setData(Qt::UserRole, i);
                    activeItem->setData(Qt::UserRole, i);
                    lastLoginItem->setData(Qt::UserRole, i);
                    createdByItem->setData(Qt::UserRole, i);
                    
                    userTable->setItem(i, 0, usernameItem);
                    userTable->setItem(i, 1, roleItem);
                    userTable->setItem(i, 2, activeItem);
                    userTable->setItem(i, 3, lastLoginItem);
                    userTable->setItem(i, 4, createdByItem);
                } catch (const std::exception& e) {
                    statusLabel->setText(QString("Error populating table row %1: %2").arg(i).arg(e.what()));
                    continue; // Skip this row and continue with the next one
                } catch (...) {
                    statusLabel->setText(QString("Unknown error populating table row %1").arg(i));
                    continue; // Skip this row and continue with the next one
                }
            }
            
            // Re-enable sorting after population is complete
            userTable->setSortingEnabled(true);
            
            statusLabel->setText(QString("Loaded %1 users").arg(userData.size()));
        } else {
            statusLabel->setText("No users found");
        }
    } catch (const std::exception& e) {
        statusLabel->setText("Error parsing user data");
        showErrorMessage("Data Error", QString("Failed to parse user data: %1").arg(e.what()));
    } catch (...) {
        statusLabel->setText("Unknown parsing error");
        showErrorMessage("Data Error", "Unknown error occurred while parsing user data");
    }
}

void UserManagementDialog::handleDeleteResponse(const QJsonDocument& doc)
{
    try {
        QJsonObject obj = doc.object();
        
        if (obj.contains("success") && obj["success"].toBool()) {
            // Show success popup with modern Havoc styling
            QMessageBox successDialog(this);
            successDialog.setWindowTitle("Success");
            successDialog.setText("User deleted successfully");
            successDialog.setIcon(QMessageBox::Information);
            successDialog.setStandardButtons(QMessageBox::Ok);
            
            // Apply modern Havoc dark theme styling
            successDialog.setStyleSheet(
                "QMessageBox {"
                "    background-color: #2b2b2b;"
                "    color: #ffffff;"
                "    border: 2px solid #404040;"
                "    border-radius: 8px;"
                "}"
                "QMessageBox QLabel {"
                "    color: #ffffff;"
                "    background-color: transparent;"
                "    border: none;"
                "    font-size: 14px;"
                "    padding: 10px;"
                "}"
                "QMessageBox QPushButton {"
                "    background-color: #28a745;"
                "    color: #ffffff;"
                "    border: 2px solid #1e7e34;"
                "    border-radius: 6px;"
                "    padding: 8px 16px;"
                "    font-size: 13px;"
                "    font-weight: bold;"
                "    min-width: 80px;"
                "    margin: 4px;"
                "}"
                "QMessageBox QPushButton:hover {"
                "    background-color: #34ce57;"
                "    border: 2px solid #61dafb;"
                "}"
                "QMessageBox QPushButton:pressed {"
                "    background-color: #1e7e34;"
                "}"
            );
            
            // Show the dialog and refresh user list when OK is clicked
            if (successDialog.exec() == QMessageBox::Ok) {
                refreshUserList();
            }
            
            statusLabel->setText("User deleted successfully");
        } else {
            QString message = obj.contains("message") ? obj["message"].toString() : "Delete operation failed";
            statusLabel->setText("Delete failed");
            showErrorMessage("Delete Failed", message);
        }
    } catch (const std::exception& e) {
        statusLabel->setText("Error parsing delete response");
        showErrorMessage("Parse Error", QString("Failed to parse delete response: %1").arg(e.what()));
    } catch (...) {
        statusLabel->setText("Unknown delete response error");
        showErrorMessage("Error", "Unknown error occurred while processing delete response");
    }
}

void UserManagementDialog::onCreateUserClicked()
{
    // Ensure we have a valid session token
    if (sessionToken.isEmpty()) {
        showErrorMessage("Authentication Error", "No valid session token available. Please refresh the user list.");
        return;
    }
    
    // Create and show the CreateUserDialog
    CreateUserDialog createDialog(sessionToken, this);
    
    if (createDialog.exec() == QDialog::Accepted) {
        // User was created successfully, refresh the user list
        refreshUserList();
        showSuccessMessage("User created successfully!");
    }
}

void UserManagementDialog::onEditUserClicked()
{
    // Validate userTable pointer
    if (!userTable) {
        showErrorMessage("Error", "User table not initialized");
        return;
    }
    
    int currentRow = userTable->currentRow();
    if (currentRow < 0 || currentRow >= userTable->rowCount()) {
        showErrorMessage("No Selection", "Please select a user to edit.");
        return;
    }
    
    // Get user data for the selected row (handles sorting)
    QJsonObject selectedUser = getUserDataForRow(currentRow);
    if (selectedUser.isEmpty()) {
        showErrorMessage("Data Error", "Unable to retrieve user data for editing.");
        return;
    }
    
    QString username = selectedUser["username"].toString();
    if (username.isEmpty()) {
        showErrorMessage("Data Error", "Selected user has no username.");
        return;
    }
    
    // Ensure we have a valid session token
    if (sessionToken.isEmpty()) {
        showErrorMessage("Authentication Error", "No valid session token available. Please refresh the user list.");
        return;
    }
    
    // Open EditUserDialog with selected user data and session token
    EditUserDialog editDialog(selectedUser, sessionToken, this);
    
    // Show the edit dialog and handle success
    if (editDialog.exec() == QDialog::Accepted) {
        // Show success popup with modern Havoc styling
        QMessageBox successDialog(this);
        successDialog.setWindowTitle("Success");
        successDialog.setText("User updated successfully");
        successDialog.setIcon(QMessageBox::Information);
        successDialog.setStandardButtons(QMessageBox::Ok);
        
        // Apply modern Havoc dark theme styling
        successDialog.setStyleSheet(
            "QMessageBox {"
            "    background-color: #2b2b2b;"
            "    color: #ffffff;"
            "    border: 2px solid #404040;"
            "    border-radius: 8px;"
            "}"
            "QMessageBox QLabel {"
            "    color: #ffffff;"
            "    background-color: transparent;"
            "    border: none;"
            "    font-size: 14px;"
            "    padding: 10px;"
            "}"
            "QMessageBox QPushButton {"
            "    background-color: #28a745;"
            "    color: #ffffff;"
            "    border: 2px solid #1e7e34;"
            "    border-radius: 6px;"
            "    padding: 8px 16px;"
            "    font-size: 13px;"
            "    font-weight: bold;"
            "    min-width: 80px;"
            "    margin: 4px;"
            "}"
            "QMessageBox QPushButton:hover {"
            "    background-color: #34ce57;"
            "    border: 2px solid #61dafb;"
            "}"
            "QMessageBox QPushButton:pressed {"
            "    background-color: #1e7e34;"
            "}"
        );
        
        // Show the dialog and refresh user list when OK is clicked
        if (successDialog.exec() == QMessageBox::Ok) {
            refreshUserList();
        }
    }
}

void UserManagementDialog::onDeleteUserClicked()
{
    // Validate userTable pointer
    if (!userTable) {
        showErrorMessage("Error", "User table not initialized");
        return;
    }
    
    int currentRow = userTable->currentRow();
    if (currentRow < 0 || currentRow >= userTable->rowCount()) {
        showErrorMessage("No Selection", "Please select a user to delete.");
        return;
    }
    
    // Safe username extraction with null checks
    QTableWidgetItem* usernameItem = userTable->item(currentRow, 0);
    if (!usernameItem) {
        showErrorMessage("Data Error", "Unable to retrieve username for selected user.");
        return;
    }
    
    QString username = usernameItem->text();
    if (username.isEmpty()) {
        showErrorMessage("Data Error", "Selected user has no username.");
        return;
    }
    
    // Confirm deletion with custom styled dialog
    QMessageBox confirmDialog(this);
    confirmDialog.setWindowTitle("Confirm Delete");
    confirmDialog.setText(QString("Are you sure you want to delete user '%1'?").arg(username));
    confirmDialog.setInformativeText("This action cannot be undone.");
    confirmDialog.setIcon(QMessageBox::Warning);
    confirmDialog.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    confirmDialog.setDefaultButton(QMessageBox::No);
    
    // Apply modern Havoc dark theme styling consistent with other dialogs
    confirmDialog.setStyleSheet(
        "QMessageBox {"
        "    background-color: #2b2b2b;"
        "    color: #ffffff;"
        "    border: 2px solid #404040;"
        "    border-radius: 8px;"
        "}"
        "QMessageBox QLabel {"
        "    color: #ffffff;"
        "    background-color: transparent;"
        "    border: none;"
        "    font-size: 14px;"
        "    padding: 10px;"
        "}"
        "QMessageBox QPushButton {"
        "    background-color: #404040;"
        "    color: #ffffff;"
        "    border: 2px solid #606060;"
        "    border-radius: 6px;"
        "    padding: 8px 16px;"
        "    font-size: 13px;"
        "    font-weight: bold;"
        "    min-width: 80px;"
        "    margin: 4px;"
        "}"
        "QMessageBox QPushButton:hover {"
        "    background-color: #4a4a4a;"
        "    border: 2px solid #61dafb;"
        "}"
        "QMessageBox QPushButton:pressed {"
        "    background-color: #363636;"
        "}"
        "QMessageBox QPushButton[text='&Yes'] {"
        "    background-color: #dc3545;"
        "    border: 2px solid #c82333;"
        "}"
        "QMessageBox QPushButton[text='&Yes']:hover {"
        "    background-color: #e94d59;"
        "    border: 2px solid #61dafb;"
        "}"
        "QMessageBox QPushButton[text='&Yes']:pressed {"
        "    background-color: #c42430;"
        "}"
    );
    
    if (confirmDialog.exec() == QMessageBox::Yes) {
        QJsonObject data;
        data["username"] = username;
        makeApiRequest("/auth/users/delete", "DELETE", data);
    }
}

void UserManagementDialog::onAssignAgentsClicked()
{
    // Validate userTable pointer
    if (!userTable) {
        showErrorMessage("Error", "User table not initialized");
        return;
    }
    
    int currentRow = userTable->currentRow();
    if (currentRow < 0 || currentRow >= userTable->rowCount()) {
        showErrorMessage("No Selection", "Please select a user to assign agents to.");
        return;
    }
    
    // Safe role extraction with null checks
    QTableWidgetItem* roleItem = userTable->item(currentRow, 1);
    if (!roleItem) {
        showErrorMessage("Data Error", "Unable to retrieve role for selected user.");
        return;
    }
    
    QString role = roleItem->text();
    if (role.isEmpty()) {
        showErrorMessage("Data Error", "Selected user has no role information.");
        return;
    }
    
    if (role != "agent-operator") {
        showErrorMessage("Invalid Role", "Agent assignment is only available for users with 'agent-operator' role.");
        return;
    }
    
    // Get username from current row
    QTableWidgetItem* usernameItem = userTable->item(currentRow, 0);
    if (!usernameItem) {
        showErrorMessage("Data Error", "Unable to retrieve username for selected user.");
        return;
    }
    
    QString username = usernameItem->text();
    if (username.isEmpty()) {
        showErrorMessage("Data Error", "Selected user has no username.");
        return;
    }
    
    // Open AgentAssignmentDialog
    auto dialog = new HavocNamespace::UserInterface::Dialogs::AgentAssignmentDialog(username, sessionToken, this);
    dialog->exec();
    delete dialog;
}

void UserManagementDialog::onRefreshClicked()
{
    refreshUserList();
}

void UserManagementDialog::onUserSelectionChanged()
{
    // Validate userTable pointer first
    if (!userTable) {
        statusLabel->setText("Error: User table not initialized");
        return;
    }
    
    int currentRow = userTable->currentRow();
    bool hasSelection = currentRow >= 0 && currentRow < userTable->rowCount();
    
    // Validate selection bounds
    if (!hasSelection) {
        editUserButton->setEnabled(false);
        deleteUserButton->setEnabled(false);
        assignAgentsButton->setEnabled(false);
        return;
    }
    
    editUserButton->setEnabled(true);
    deleteUserButton->setEnabled(true);
    
    // Safe role check with comprehensive null validation
    try {
        QTableWidgetItem* roleItem = userTable->item(currentRow, 1);
        
        // Validate pointer before accessing
        if (roleItem == nullptr) {
            // Handle case where role data is missing
            assignAgentsButton->setEnabled(false);
            statusLabel->setText("Warning: Missing role data for selected user");
            return;
        }
        
        // Additional validation of the item content
        QString role = roleItem->text();
        if (role.isEmpty()) {
            assignAgentsButton->setEnabled(false);
            statusLabel->setText("Warning: Empty role data for selected user");
            return;
        }
        
        // Enable agent assignment only for agent-operator role
        assignAgentsButton->setEnabled(role == "agent-operator");
        
    } catch (const std::exception& e) {
        // Catch any unexpected exceptions during item access
        assignAgentsButton->setEnabled(false);
        statusLabel->setText(QString("Error accessing user data: %1").arg(e.what()));
    } catch (...) {
        // Catch any other exceptions
        assignAgentsButton->setEnabled(false);
        statusLabel->setText("Unknown error accessing user data");
    }
}

void UserManagementDialog::showErrorMessage(const QString& title, const QString& message)
{
    // Use Qt's standard message box with dark theme
    QMessageBox msgBox(this);
    msgBox.setWindowTitle(title);
    msgBox.setText(message);
    msgBox.setIcon(QMessageBox::Warning);
    msgBox.setStandardButtons(QMessageBox::Ok);
    msgBox.setStyleSheet(R"(
        QMessageBox {
            background-color: #2b2b2b;
            color: #ffffff;
        }
        QMessageBox QPushButton {
            background-color: #404040;
            color: #ffffff;
            border: 1px solid #606060;
            border-radius: 6px;
            padding: 8px 16px;
            min-width: 80px;
        }
        QMessageBox QPushButton:hover {
            background-color: #4a4a4a;
            border: 1px solid #61dafb;
        }
    )");
    msgBox.exec();
}

void UserManagementDialog::showSuccessMessage(const QString& message)
{
    statusLabel->setText(message);
    statusLabel->setStyleSheet("color: #4CAF50; font-weight: bold;");
    
    // Reset status color after 3 seconds
    QTimer::singleShot(3000, [this]() {
        statusLabel->setStyleSheet("color: #cccccc;");
    });
}

QJsonObject UserManagementDialog::getUserDataForRow(int row) const
{
    // Get the username from the table to find the corresponding user data
    if (!userTable || row < 0 || row >= userTable->rowCount()) {
        return QJsonObject();
    }
    
    QTableWidgetItem* usernameItem = userTable->item(row, 0);
    if (!usernameItem) {
        return QJsonObject();
    }
    
    QString username = usernameItem->text();
    
    // Find the user data by username (in case table is sorted)
    for (int i = 0; i < userData.size(); ++i) {
        QJsonObject user = userData[i].toObject();
        if (user.contains("username") && user["username"].toString() == username) {
            return user;
        }
    }
    
    return QJsonObject();
}
