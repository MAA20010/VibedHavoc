#ifndef HAVOC_ADMINFEATUREDIALOG_HPP
#define HAVOC_ADMINFEATUREDIALOG_HPP

#include <global.hpp>

class AdminFeatureDialog : public QDialog
{
public:
    explicit AdminFeatureDialog(const QString& title, const QString& message, QWidget* parent = nullptr);

private:
    void setupUi();
    
    QString dialogTitle;
    QString dialogMessage;
    
    QVBoxLayout* mainLayout;
    QHBoxLayout* buttonLayout;
    QLabel* titleLabel;
    QLabel* messageLabel;
    QLabel* iconLabel;
    QPushButton* okButton;
};

#endif // HAVOC_ADMINFEATUREDIALOG_HPP
