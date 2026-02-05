# clearance_payments/webhooks.py
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponseBadRequest
from .models import Payment
import json
from django.utils import timezone

@csrf_exempt
def telebirr_webhook(request):
    # Telebirr will POST to this endpoint when a transaction completes.
    # Validate signature if Telebirr requires it (check docs) — IMPORTANT for production.
    try:
        data = json.loads(request.body.decode('utf-8'))
    except Exception:
        return HttpResponseBadRequest('invalid json')

    # Example fields: order_id, amount, status, transaction_id
    # Adapt to Telebirr's actual webhook payload.
    order_id = data.get('order_id')
    status = data.get('status')  # e.g. 'SUCCESS'
    txn_id = data.get('transaction_id')

    if not order_id:
        return HttpResponseBadRequest('missing order_id')

    try:
        payment = Payment.objects.get(id=order_id)
    except Payment.DoesNotExist:
        return HttpResponseBadRequest('unknown order')

    if status == 'SUCCESS':
        payment.is_paid = True
        payment.paid_at = timezone.now()
        payment.reference = txn_id
        payment.save()
        return JsonResponse({'result': 'ok'})
    else:
        return JsonResponse({'result': 'ignored'}, status=200)
