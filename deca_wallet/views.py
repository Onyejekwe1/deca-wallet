from django.contrib.auth.hashers import check_password
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from django.shortcuts import render
from pip._vendor import requests
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import NotAcceptable
from rest_framework.views import APIView
from rest_framework.permissions import *
from rest_framework.response import Response
from rest_framework import status
from .models import User, Elite, Noob, Wallet, WalletTransaction
from django.db import transaction
from . import serializers
from .services.currency_service import fetch_currency
from .services.admin_service import IsAdmin


# Create your views here.
class RegisterUser(APIView):
    permission_classes = [AllowAny]

    # noinspection PyMethodMayBeStatic
    def post(self, request):

        with transaction.atomic():
            user_data = {
                "first_name": request.data["first_name"],
                "last_name": request.data["last_name"],
                "email": request.data["email"],
                "username": request.data["username"],
                "password": request.data["password"]
            }
            user_serializer = serializers.UserSerializer(data=user_data)

            if user_serializer.is_valid():
                user = user_serializer.save()
                user.set_password(request.data["password"])

                wallet_data = {
                    "user_id": user.id,
                    "wallet_category": request.data["wallet_category"],
                    "currency_main": request.data["currency_main"]
                }
                if request.data['wallet_category'].capitalize() == 'Elite':
                    elite_serializer = serializers.EliteSerializer(data=wallet_data)
                    if elite_serializer.is_valid():
                        elite_serializer.save()
                    else:
                        return Response(
                            dict(elite_serializer.errors),
                            status=status.HTTP_400_BAD_REQUEST)

                if request.data['wallet_category'].capitalize() == 'Noob':
                    noob_serializer = serializers.NoobSerializer(data=wallet_data)
                    if noob_serializer.is_valid():
                        noob_serializer.save()
                    else:
                        return Response(
                            dict(noob_serializer.errors),
                            status=status.HTTP_400_BAD_REQUEST)

                default_wallet = {
                    "user_id": user.id,
                    "currency": request.data["currency_main"],
                    "wallet_balance": 0,
                    "main_wallet": True
                }

                wallet_serializer = serializers.WalletSerializer(data=default_wallet)
                if wallet_serializer.is_valid():
                    wallet_serializer.save()
                else:
                    return Response(
                        dict(wallet_serializer.errors),
                        status=status.HTTP_400_BAD_REQUEST)

                profile_data = {
                    "user_id": user.id,
                    "first_name": request.data["first_name"],
                    "last_name": request.data["last_name"],
                    "email": request.data["email"],
                    "wallet_category": request.data["wallet_category"],
                    "currency_main": request.data["currency_main"]
                }

                return Response(
                    profile_data,
                    status=status.HTTP_201_CREATED)
            else:
                return Response(
                    user_serializer.errors,
                    status=status.HTTP_400_BAD_REQUEST)


class Login(APIView):
    permission_classes = [AllowAny]

    # noinspection PyMethodMayBeStatic
    def post(self, request):
        try:
            email = request.data.get('email', '')
            password = request.data.get('password', '')

            if email is None or password is None:
                return Response(
                    dict(invalid_credential='Email and password compulsory'),
                    status=status.HTTP_400_BAD_REQUEST)
            try:
                db_user = User.objects.get(email=email.strip().lower())
            except ObjectDoesNotExist:
                return Response(
                    dict(invalid_credential=f'User with email {email} does not exist'),
                    status=status.HTTP_400_BAD_REQUEST)

            user = check_password(password, db_user.password)

            if not user:
                return Response(
                    dict(invalid_credential='Email and/or password incorrect'),
                    status=status.HTTP_400_BAD_REQUEST)

            access_token, _ = Token.objects.get_or_create(user=db_user)
            return Response(dict(token=access_token.key), status=status.HTTP_200_OK)


        except Exception as e:
            return Response(
                data={
                    "message": "Error Occurred.",
                    "error": str(e)
                },
                status=status.HTTP_400_BAD_REQUEST)


class Wallets(APIView):
    permission_classes = [IsAuthenticated]

    # Add a wallet for Elite Users
    def post(self, request):

        # first Check if user is an Elite as only Elites can have multiple wallets
        try:
            Elite.objects.get(user_id=request.user)

        except PermissionDenied:
            return Response(dict(message="Only Elites can have multiple wallets."),
                            status=status.HTTP_403_FORBIDDEN)

        # Get all user wallets
        user_wallets = Wallet.objects.filter(user_id=request.user)
        for wallet in user_wallets.all():
            if wallet.currency == request.data["currency"].upper():
                return Response(dict(message="Wallet with currency already exists."),
                                status=status.HTTP_406_NOT_ACCEPTABLE)

        wallet_data = {
            "currency": request.data["currency"].upper(),
            "balance": 0,
            "main": False,
            "user_id": request.user.id
        }

        wallet_serializer = serializers.WalletSerializer(data=wallet_data)

        if wallet_serializer.is_valid():
            wallet_serializer.save()
            return Response(dict(message="Operation Successful"), status=status.HTTP_201_CREATED)
        else:
            return Response(
                dict(wallet_serializer.errors),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Get all User wallet
    def get(self, request):
        user = request.user.id

        # Get all wallets that belong to the user
        user_wallets = Wallet.objects.filter(user_id=user)
        wallets_record = []
        for wallet in user_wallets.all():
            wallets_record.append(("Currency: " + wallet.currency, "Balance: " + wallet.balance))

        user_account = User.objects.get(id=user)

        try:
            wallet_category = Elite.objects.get(user_id=request.user).wallet_category

        except NotAcceptable:
            wallet_category = Noob.objects.get(user_id=request.user).wallet_type

        wallet_info = {
            "Name": user_account.first_name + " " + user_account.last_name,
            "Wallet Type": wallet_category,
            "Wallets": wallets_record
        }
        return Response(
            wallet_info,
            status=status.HTTP_200_OK
        )


# Fund Wallet View
class Fund(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        amount = request.data["amount"]
        amount_currency = request.data["amount_currency"].upper()

        try:
            user_type = Elite.objects.get(user_id=user).wallet_category
        except NotAcceptable:
            user_type = Noob.objects.get(user_id=user).wallet_category

        # If User is an elite
        if user_type == 'Elite':

            wallets = Wallet.objects.filter(user_id=user)
            for wallet in wallets.all():
                if wallet.currency == amount_currency:
                    new_balance = float(wallet.balance) + float(amount)
                    funded_wallet = wallet
                    funding = {
                        "balance": new_balance
                    }
                    wallet_serializer = serializers.WalletSerializer(funded_wallet, data=funding, partial=True)
                    if wallet_serializer.is_valid():
                        wallet_serializer.save()

                        # Save transaction to DB
                        wallet_transaction_data = {
                            "user_id": request.user.id,
                            "wallet_id": funded_wallet.id,
                            "transaction_category": "Funding",
                            "amount": amount,
                            "currency": amount_currency,
                            "operation_status": "successful"
                        }

                        transaction_serializer = serializers.WalletTransactionSerializer(data=wallet_transaction_data)
                        if transaction_serializer.is_valid():
                            transaction_serializer.save()
                        else:
                            return Response(
                                dict(transaction_serializer.errors),
                                status=status.HTTP_400_BAD_REQUEST)

                        response_data = {
                            "Message": "Wallet funded successfully",
                            "Wallet": wallet.currency,
                            "Balance": new_balance
                        }
                        return Response(
                            response_data,
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            dict(wallet_serializer.errors),
                            status=status.HTTP_400_BAD_REQUEST)

            else:
                balance = amount

                new_wallet = {
                    "user_id": user.id,
                    "currency": amount_currency,
                    "balance": balance,
                    "main": False
                }

                wallet_serializer = serializers.WalletSerializer(data=new_wallet)
                if wallet_serializer.is_valid():
                    wallet_serializer.save()

                    # Save transaction to DB
                    wallet_transaction_data = {
                        "user_id": request.user.id,
                        "wallet_id": wallet_serializer.instance.id,
                        "transaction_category": "Funding",
                        "amount": amount,
                        "currency": amount_currency,
                        "operation_status": "successful"
                    }

                    transaction_serializer = serializers.WalletTransactionSerializer(data=wallet_transaction_data)
                    if transaction_serializer.is_valid():
                        transaction_serializer.save()
                    else:
                        return Response(
                            dict(transaction_serializer.errors),
                            status=status.HTTP_400_BAD_REQUEST)

                    response_data = {
                        "Message": "Wallet funded successfully",
                        "Wallet": amount_currency,
                        "Balance": balance
                    }
                    return Response(
                        response_data,
                        status=status.HTTP_200_OK
                    )
                else:
                    return Response(
                        dict(wallet_serializer.errors),
                        status=status.HTTP_400_BAD_REQUEST)

        if user_type == 'Noob':

            wallet = Wallet.objects.get(user_id=user)

            main_currency = wallet.currency

            fund_currency = fetch_currency(amount_currency)

            convert_string = fund_currency + "_" + main_currency

            url = "https://free.currconv.com/api/v7/convert?q=" + convert_string + "&compact=ultra&apiKey=066f3d02509dab104f69"
            response = requests.get(url).json()
            rate = response[convert_string]

            funding = rate * float(amount)

            new_balance = float(wallet.balance) + funding

            funding = {
                "balance": new_balance
            }

            wallet_serializer = serializers.WalletSerializer(wallet, data=funding, partial=True)
            if wallet_serializer.is_valid():
                wallet_serializer.save()

                wallet_transaction_data = {
                    "user_id": request.user.id,
                    "wallet_id": wallet_serializer.instance.id,
                    "transaction_category ": "Funding",
                    "amount": amount,
                    "currency": amount_currency,
                    "operation_status": "successful"
                }

                transaction_serializer = serializers.WalletTransactionSerializer(data=wallet_transaction_data)
                if transaction_serializer.is_valid():
                    transaction_serializer.save()
                else:
                    return Response(
                        dict(transaction_serializer.errors),
                        status=status.HTTP_400_BAD_REQUEST)

                response_data = {
                    "Message": "Wallet funded successfully",
                    "Wallet": wallet.currency,
                    "Balance": new_balance
                }
                return Response(
                    response_data,
                    status=status.HTTP_200_OK
                )


class Withdrawal(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):

        amount = request.data["amount"]
        currency = request.data["currency"].upper()
        user = request.user

        try:
            user_type = Elite.objects.get(user_id=user).wallet_type
        except NotAcceptable:
            user_type = Noob.objects.get(user_id=user).wallet_type

        if user_type == 'Elite':

            wallets = Wallet.objects.filter(user_id=user)
            for wallet in wallets.all():
                if wallet.currency == currency:

                    if float(wallet.balance) < float(amount):
                        return Response(
                            dict(errors="Insufficient Funds"),
                            status=status.HTTP_406_NOT_ACCEPTABLE)

                    balance_after_withdrawal = float(wallet.balance) - float(amount)
                    withdrawn_wallet = Wallet.objects.get(currency=currency)
                    withdrawal = {
                        "balance": balance_after_withdrawal
                    }

                    wallet_serializer = serializers.WalletSerializer(withdrawn_wallet, data=withdrawal, partial=True)
                    if wallet_serializer.is_valid():
                        wallet_serializer.save()

                        transaction_data = {
                            "user_id": request.user.id,
                            "wallet_id": withdrawn_wallet.id,
                            "transaction_category": "Withdrawal",
                            "amount": amount,
                            "currency": currency,
                            "operation_status": "successful"
                        }

                        transaction_serializer = serializers.WalletTransactionSerializer(data=transaction_data)
                        if transaction_serializer.is_valid():
                            transaction_serializer.save()
                        else:
                            return Response(
                                dict(transaction_serializer.errors),
                                status=status.HTTP_400_BAD_REQUEST)

                        response_data = {
                            "Message": "Amount Withdrawn successfully",
                            "Wallet": wallet.currency,
                            "Balance": balance_after_withdrawal
                        }
                        return Response(
                            response_data,
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            dict(wallet_serializer.errors),
                            status=status.HTTP_400_BAD_REQUEST)

            else:
                wallets = Wallet.objects.filter(user_id=user)
                for wallet in wallets.all():
                    if wallet.main:
                        main_currency = wallet.currency

                        withdrawal_currency = fetch_currency(currency)

                        convert_string = withdrawal_currency + "_" + main_currency

                        # get conversion rate
                        url = "https://free.currconv.com/api/v7/convert?q=" + convert_string + "&compact=ultra&apiKey=066f3d02509dab104f69"
                        response = requests.get(url).json()
                        rate = response[convert_string]

                        # calculate amount to be funded based on conversion rate
                        withdrawal = rate * float(amount)

                        # check that the balance is up to the amount to be withdrawn
                        if float(wallet.balance) < float(withdrawal):
                            return Response(
                                dict(errors="Insufficient Funds"),
                                status=status.HTTP_406_NOT_ACCEPTABLE)

                        # subtract the amount from the balance
                        balance_after_withdrawal = float(wallet.balance) - float(withdrawal)

                        withdrawal_wallet = {
                            "balance": balance_after_withdrawal
                        }
                        wallet_serializer = serializers.WalletSerializer(wallet, data=withdrawal_wallet,
                                                                         partial=True)
                        if wallet_serializer.is_valid():
                            wallet_serializer.save()

                            transaction_data = {
                                "user_id": request.user.id,
                                "wallet_id": wallet.id,
                                "transaction_category": "Withdrawal",
                                "amount": withdrawal,
                                "currency": wallet.currency,
                                "operation_status": "successful"
                            }

                            transaction_serializer = serializers.WalletTransactionSerializer(data=transaction_data)
                            if transaction_serializer.is_valid():
                                transaction_serializer.save()
                            else:
                                return Response(
                                    dict(transaction_serializer.errors),
                                    status=status.HTTP_400_BAD_REQUEST)

                            response_data = {
                                "Message": "Withdrawal successful",
                                "Wallet": wallet.currency,
                                "Balance": balance_after_withdrawal
                            }
                            return Response(
                                response_data,
                                status=status.HTTP_200_OK
                            )

        if user_type == 'Noob':

            wallet = Wallet.objects.get(user_id=user)

            if wallet.currency == currency:
                if float(wallet.balance) < float(amount):
                    return Response(
                        dict(errors="Insufficient Funds"),
                        status=status.HTTP_406_NOT_ACCEPTABLE)

                # Save transaction to DB
                transaction_data = {
                    "user_id": request.user.id,
                    "wallet_id": wallet.id,
                    "transaction_category": "Withdrawal",
                    "amount": amount,
                    "currency": currency,
                    "operation_status ": "pending"
                }

                transaction_serializer = serializers.WalletTransactionSerializer(data=transaction_data)
                if transaction_serializer.is_valid():
                    transaction_serializer.save()
                    response_data = {
                        "Message": "Withdrawal sent for Approval."
                    }
                    return Response(
                        response_data,
                        status=status.HTTP_200_OK
                    )
                else:
                    return Response(
                        dict(transaction_serializer.errors),
                        status=status.HTTP_400_BAD_REQUEST)

            else:
                main_currency = wallet.currency

                # get funding currency
                withdrawal_currency = fetch_currency(currency)

                # generate conversion string
                convert_string = withdrawal_currency + "_" + main_currency

                # get conversion rate
                url = "https://free.currconv.com/api/v7/convert?q=" + convert_string + "&compact=ultra&apiKey=066f3d02509dab104f69"
                response = requests.get(url).json()
                rate = response[convert_string]

                # calculate amount to be funded based on conversion rate
                withdrawal = rate * float(amount)

                # check that the balance is up to the amount to be withdrawn
                if float(wallet.balance) < float(withdrawal):
                    return Response(
                        dict(errors="Insufficient Funds"),
                        status=status.HTTP_400_BAD_REQUEST)

                # Save transaction to DB
                transaction_data = {
                    "user_id": request.user.id,
                    "wallet_id": wallet.id,
                    "transaction_category": "Withdrawal",
                    "amount": amount,
                    "currency": currency,
                    "operation_status": "pending"
                }

                transaction_serializer = serializers.WalletTransactionSerializer(data=transaction_data)
                if transaction_serializer.is_valid():
                    transaction_serializer.save()
                    response_data = {
                        "Message": "Withdrawal sent for Approval."
                    }
                    return Response(
                        response_data,
                        status=status.HTTP_200_OK
                    )
                else:
                    return Response(
                        dict(transaction_serializer.errors),
                        status=status.HTTP_400_BAD_REQUEST)


class WithdrawalAwaitingApproval(APIView):
    permission_classes = [IsAdmin]

    # Get all transactions that belong to an Account
    def get(self, request):
        # Get all transactions that are pending
        transactions = WalletTransaction.objects.filter(operation_status="pending")
        transaction_record = []
        for trans in transactions.all():
            transaction_record.append(
                (
                    "transaction_id: " + str(trans.id),
                    "wallet_id: " + str(trans.wallet_id),
                    "Currency: " + trans.currency,
                    "Amount: " + trans.amount,
                    "transaction_category: " + trans.transaction_category,
                    "Date: " + trans.created_at.strftime("%m/%d/%Y"),
                    "operation_status: " + trans.status
                )
            )

        transaction_info = {
            "Pending Transactions": transaction_record
        }
        return Response(
            transaction_info,
            status=status.HTTP_200_OK
        )


class Approve(APIView):
    permission_classes = [IsAdmin]

    def post(self, request):
        transaction_id = request.data["transaction_id"]

        wallet_transact = WalletTransaction.objects.get(id=transaction_id)

        wallet = Wallet.objects.get(id=wallet_transact.wallet_id.id)

        main_curr = wallet.currency

        withdrawal_curr = wallet_transact.currency

        convert_str = withdrawal_curr + "_" + main_curr

        url = "https://free.currconv.com/api/v7/convert?q=" + convert_str + "&compact=ultra&apiKey=066f3d02509dab104f69"
        response = requests.get(url).json()
        rate = response[convert_str]

        withdrawal = rate * float(wallet_transact.amount)

        new_balance = float(wallet.balance) - float(withdrawal)

        withdrawal_wallet = {
            "wallet_balance": new_balance
        }

        wallet_serializer = serializers.WalletSerializer(wallet, data=withdrawal_wallet,
                                                         partial=True)
        if wallet_serializer.is_valid():
            wallet_serializer.save()

            # Update transaction in DB
            transaction_data = {
                "status": "successful"
            }

            response_data = {
                "wallet_id": wallet.id,
                "transaction_category": "Withdrawal",
                "amount": withdrawal,
                "currency": wallet.currency,
                "operation_status": "successful"
            }

            transaction_serializer = serializers.WalletTransactionSerializer(wallet_transact, data=transaction_data,
                                                                             partial=True)
            if transaction_serializer.is_valid():
                transaction_serializer.save()
            else:
                return Response(
                    dict(transaction_serializer.errors),
                    status=status.HTTP_400_BAD_REQUEST)

            return Response(
                response_data,
                status=status.HTTP_200_OK
            )


class Promote(APIView):
    permission_classes = [IsAdmin]

    def post(self, request):
        with transaction.atomic():

            user_id = request.data["user_id"]

            noob_user = Noob.objects.get(user_id=user_id)

            elite_data = {
                "user_id": noob_user.user_id.id,
                "wallet_category": "Elite",
                "currency_main": noob_user.main_currency
            }

            elite_serializer = serializers.EliteSerializer(data=elite_data)
            if elite_serializer.is_valid():
                elite_serializer.save()
            else:
                return Response(
                    dict(elite_serializer.errors),
                    status=status.HTTP_400_BAD_REQUEST)

            Noob.objects.filter(user_id=user_id).delete()
            success = {
                "message": "User Promoted to Elite"
            }
            return Response(
                success,
                status=status.HTTP_200_OK
            )


class Demote(APIView):
    permission_classes = [IsAdmin]

    def post(self, request):
        with transaction.atomic():

            user_id = request.data["user_id"]

            elite_user = Elite.objects.get(user_id=user_id)

            noob_user_data = {
                "user_id": elite_user.user_id.id,
                "wallet_category": "Noob",
                "currency_main": elite_user.main_currency
            }

            noob_serializer = serializers.NoobSerializer(data=noob_user_data)
            if noob_serializer.is_valid():
                noob_serializer.save()
            else:
                return Response(
                    dict(noob_serializer.errors),
                    status=status.HTTP_400_BAD_REQUEST)

            wallets = Wallet.objects.filter(user_id=user_id)
            converted_money = 0
            for wallet in wallets.all():
                if not wallet.main:
                    # get main currency from db
                    main_curr = elite_user.main_currency
                    # get the currency
                    fund_curr = wallet.currency
                    # generate conversion string
                    convert_str = fund_curr + "_" + main_curr
                    # get conversion rate
                    url = "https://free.currconv.com/api/v7/convert?q=" + convert_str + "&compact=ultra&apiKey=066f3d02509dab104f69"
                    response = requests.get(url).json()
                    rate = response[convert_str]

                    # calculate amount to be funded based on conversion rate
                    funding = rate * float(wallet.balance)
                    # sum the balance and the new amount
                    converted_money += funding

                    # Delete the wallet data from wallets table
                    Wallet.objects.filter(id=wallet.id).delete()

            # get main wallet
            remaining_wallet = Wallet.objects.filter(user_id=user_id)
            for r_wallet in remaining_wallet:
                if r_wallet.main:
                    # Move all deposits in multiple wallet into main wallet
                    # sum the balance and the new amount
                    new_balance = float(r_wallet.balance) + converted_money

                    new_wallet_balance = {
                        "wallet_balance": new_balance
                    }

                    wallet_serializer = serializers.WalletSerializer(r_wallet, data=new_wallet_balance, partial=True)
                    if wallet_serializer.is_valid():
                        wallet_serializer.save()
                    else:
                        return Response(
                            wallet_serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST
                        )

                    Elite.objects.filter(user_id=user_id).delete()

                    success = {
                        "message": "User Demoted to Noob"
                    }
                    return Response(
                        success,
                        status=status.HTTP_200_OK
                    )
