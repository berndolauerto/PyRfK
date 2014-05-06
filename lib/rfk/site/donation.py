import datetime
from flask import Blueprint, render_template, url_for
from rfk.database.donations import Donation
__author__ = 'teddydestodes'

donation = Blueprint('donation', __name__)

try:
    from rfk.armor import get_serviceproxy
    @donation.route('/')
    def list():
        sp = get_serviceproxy()
        transactions = []
        for transaction in sp.listtransactions():
            print transaction
            if transaction['category'] != 'recieve':  # no one should ever know
                transactions.append({'timestamp': datetime.datetime.fromtimestamp(transaction['time']),
                                     'amount': transaction['amount'],
                                     'currency': 'BTC',
                                     'comment': ''})
        return render_template('donations.html', TITLE='Donations', donations=transactions)

    def create_menu(endpoint):
        menu = {'name': 'Donations',
                'active': endpoint == 'donation.list',
                'url': url_for('donation.list')}
        return menu
    donation.create_menu = create_menu

except ImportError as e:
    print e