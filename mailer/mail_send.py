import webapp2
from google.appengine.api import mail


class SendStatistics(webapp2.RequestHandler):
    def post(self, data):
        user_address = 'jasper.gae@gmail.com'
        print data

        if not mail.is_email_valid(user_address):
            # prompt user to enter a valid address
            pass
        else:

            sender_address = "Chasing Mallpoints <jasper.gae@gmail.com>"
            subject = "Changes from previous to last scrape "
            body = """

                %s
                """ % data

            mail.send_mail(sender_address, user_address, subject, body)
